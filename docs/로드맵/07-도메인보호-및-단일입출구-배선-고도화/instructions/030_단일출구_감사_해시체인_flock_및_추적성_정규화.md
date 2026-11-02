# 030. 단일 출구 감사 해시 체인·`flock` 탑재 및 추적성 정규화 구현지시서

> **상태**: `Done`
> **선행 조건**: 020 단계 (순수 PDP 스코프 검증 복원 및 도메인 이벤트 구조 분리) 완료
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md) | **감사 근거**: [도메인 보호 및 배선 감사 보고서](../../../../DOMAIN_PROTECTION_AND_WIRING_AUDIT_REPORT.md)

---

## 1. 목적 (Context & Why)

본 지시서는 감사 보고서에서 적발된 **AP-04(다중 출구 감사 기록으로 인한 `Action`/`Decision`/`Reason` 스키마 파편화)**, **AP-05(`pdp.Decide` 등의 독자적 `TraceID` 즉석 생성으로 인한 추적 사슬 단절)**, 그리고 **AP-06(`audit.JSONLWriter`의 SHA-256 해시 체인 미구현 및 다중 프로세스 `syscall.Flock` 누락)**을 해결하여 **단일 입구 · 단일 출구(Single Entry / Single Exit) 감사·추적 파이프라인**을 확립하는 단계다.

보안 및 아키텍처 불변식에 따라:
1. **단일 출구 SHA-256 암호학적 해시 체인 강제 (`prev_hash` → `curr_hash`)**:
   - `internal/audit/audit.go`의 `JSONLWriter.Log`가 이벤트를 기록할 때, 호출자가 일일이 해시를 계산할 필요 없이 **출구 기록기(`JSONLWriter`)가 단일 관문으로서 직전 레코드의 `curr_hash`를 이어받아 현재 레코드의 `PrevHash`(`prev_hash`)와 `CurrHash`(`curr_hash`)를 강제로 계산·부착**한다.
   - `audit.VerifyHashChain(path string) error` 함수를 구현하여, 파일 내 단 1바이트의 변조나 줄 삽입/삭제가 발생하면 즉시 `*domain.Error`(`ReasonAuditIntegrityBroken`, `ExitAuditFailure = 15`)를 반환하게 한다.
2. **다중 프로세스 원자적 잠금 (`syscall.Flock`)**:
   - 부모(`orchestrator`)와 자식(`subagent`) OS 프로세스가 동일한 `audit.jsonl` 파일에 기록할 때 줄이 뒤섞이거나 해시 체인이 끊어지지 않도록, `JSONLWriter.Log`는 `audit.jsonl.lock`에 대해 `syscall.Flock(LOCK_EX)`을 획득한 상태에서 직전 해시 조회 및 Append + `Sync()`를 수행한다.
3. **감사 이벤트 최상위 필드 및 단일 `TraceID` 정규화**:
   - 모든 감사 이벤트는 `Metadata` 맵 안에만 사유를 숨기지 않고, 반드시 최상위 `TraceID`, `Action`(`pep.allow`, `pep.deny`, `token.issue.deny`, `token.exchange.deny`, `pdp.decide` 등), `Decision`(`"allow"` 또는 `"deny"` 소문자 표준화), `Reason`(`string(domain.Reason)`) 필드를 일관되게 채운다.
   - `pdp.Decide` 등이 상위 `TraceID`를 이어받도록 하여 단일 요청 연쇄가 100% 동일한 `TraceID`로 묶이게 한다.

---

## 2. 파급 범위와 무영향 근거 증명 및 6계층 DAG 구조

```text
Layer 3/2: [internal/authz/pep]  [internal/authz/pdp]  [internal/authn/{token,exchange,keys}]
                 │ (상위 TraceID 전달 및 표준화된 Event 필드 발행)
                 v
Layer 1:   [internal/audit/audit.go]  <-- [SINGLE EXIT AUDIT BARRIER]
           ├── Event 구조체: PrevHash, CurrHash 최상위 필드 추가 (Metadata["prev_hash"/"curr_hash"] 동기화)
           ├── NormalizeEvent(&event, clock): Decision("allow"|"deny"), Reason, Timestamp, TraceID 정규화
           ├── JSONLWriter.Log(event):
           │     1) syscall.Flock(LOCK_EX) 획득
           │     2) 파일 마지막 레코드에서 lastHash 동기화 (다중 프로세스 체인 연속성 보장!)
           │     3) PrevHash = lastHash, CurrHash = ComputeEventHash(lastHash, event)
           │     4) JSON 한 줄 기록 및 file.Sync()
           └── VerifyHashChain(path string) error: 전체 파일 해시 체인 및 원시 토큰 유출 무결성 검증
```

- **변경 파급 범위**:
  - `internal/audit/audit.go`: 해시 체인 계산, `syscall.Flock` 다중 프로세스 동기화, 이벤트 필드 정규화, `VerifyHashChain` 추가.
  - `internal/authz/pep/gateway.go`, `internal/authz/pdp/service.go`, `internal/authn/token/verifier.go`, `internal/authn/exchange/service.go`: 상위 `TraceID` 전파 및 표준 `Action`/`Decision`/`Reason` 설정.
- **무영향 근거 증명**:
  - `audit.Event`에 `PrevHash`와 `CurrHash`를 추가하면서 동시에 `Metadata["prev_hash"]`와 `Metadata["curr_hash"]`에도 동일 값을 넣어주므로, 기존 `internal/harness/assertion.go`의 해시 체인 계산 공식(`ComputeEventCurrHash`)과 100% 호환된다.

---

## 3. 세부 설계 및 인터페이스 계약

### 3.1 정규화된 감사 이벤트 및 해시 체인 명세 (`internal/audit/audit.go`)

```go
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	TraceID     string                 `json:"trace_id"`
	Step        string                 `json:"step,omitempty"`
	Actor       string                 `json:"actor"`
	AgentID     string                 `json:"agent_id,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Resource    string                 `json:"resource,omitempty"`
	Decision    string                 `json:"decision,omitempty"` // "allow" 또는 "deny" (소문자 정규화)
	Reason      string                 `json:"reason,omitempty"`   // domain.Reason 문자열 (최상위 필수 승격)
	TokenJTI    string                 `json:"token_jti,omitempty"`
	Success     bool                   `json:"success"`
	ErrorClass  string                 `json:"error_class,omitempty"`
	PrevHash    string                 `json:"prev_hash,omitempty"`
	CurrHash    string                 `json:"curr_hash,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ComputeEventHash 는 prevHash 와 이벤트의 불변 핵심 필드들을 결정론적으로 결합하여 SHA-256 해시를 계산한다.
// [결정론적 정규화 공식]:
// Go json.Marshal 의 Metadata 역직렬화 시 타입 변환(int64 -> float64) 및 time.Time 나노초 표기 차이로 인한
// False Positive(가짜 변조 탐지)를 원천 차단하기 위해, 해시 입력은 불변 핵심 필드의 고정 구분자(|) 파이프 문자열로 표준화한다:
// raw = fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%t",
//     prevHash,
//     ev.Timestamp.UTC().Format(time.RFC3339Nano),
//     ev.TraceID,
//     ev.Actor,
//     ev.Action,
//     ev.Resource,
//     ev.Decision,
//     ev.Reason,
//     ev.Success,
// )
// hash = hex(sha256(raw))
func ComputeEventHash(prevHash string, ev Event) string

// VerifyHashChain 은 지정된 JSONL 감사 파일을 처음부터 끝까지 읽어:
// 1) JSON 파싱 가능 여부
// 2) 각 레코드의 PrevHash == 직전 레코드의 CurrHash 일치 여부
// 3) 각 레코드의 CurrHash == ComputeEventHash(PrevHash, ev) 일치 여부
// 를 검증하고 위반 시 *domain.Error (ReasonAuditIntegrityBroken, ExitAuditFailure=15)를 반환한다.
func VerifyHashChain(path string) error
```

### 3.2 단일 출구 이벤트 정규화 규칙 (`NormalizeEvent`)
1. `event.Decision`이 `"ALLOW"`이면 `"allow"`로, `"DENY"`이면 `"deny"`로 소문자 정규화한다. 만약 `event.Decision`이 비어 있고 `Metadata["decision"]`이 있으면 최상위로 승격한다.
2. `event.Reason`이 비어 있고 `Metadata["reason"]`이 있으면 최상위 `event.Reason`으로 승격한다.
3. PEP 관문 최종 허용/거부 이벤트의 `Action`이 `"pep.file:read"` 형태일 경우, `Step`에 세부 단계를 보존하고 `Action`은 `"pep.allow"`(성공 시) 또는 `"pep.deny"`(실패 시)로 표준화하며, 토큰 교환 거부 시 `"token.exchange.deny"`로 표준화한다.

---

## 4. 사전 점검 및 실패 위험 분석 (Pre-Mortem)

1. **위험: 부모 프로세스와 자식 프로세스가 각각 별도의 `JSONLWriter` 인스턴스를 생성해 같은 파일에 쓸 때 메모리 내 `lastHash` 변수만 참조하면 해시 체인이 끊어짐**
   - *방어책*: `JSONLWriter.Log`는 단순히 구조체 필드의 `lastHash`만 믿지 않고, `syscall.Flock`을 획득한 상태에서 파일 크기가 0보다 크면 파일의 마지막 줄을 읽어 직전 레코드의 `curr_hash`를 확인한 뒤 그 값을 `prev_hash`로 삼아 새 레코드를 추가한다. 이 방식으로 서로 다른 OS 프로세스가 번갈아 기록해도 단일 해시 체인이 완벽하게 이어진다.
2. **위험: `ComputeEventHash`와 `harness/assertion.go`의 `computeEventHash`가 서로 다른 직렬화 방식을 쓰면 검증이 실패함**
   - *방어책*: `internal/audit`에 표준 `ComputeEventHash`를 정의하고, `internal/harness/assertion.go`가 자체 중복 계산 대신 `audit.ComputeEventHash`(및 `audit.VerifyHashChain`)를 직접 호출하도록 단일화한다.
3. **위험: 파일에서 역직렬화된 JSON 메타데이터 타입 차이(int vs float64)로 인한 사후 검증 시의 가짜 불일치(False Positive) 위험**
   - *방어책*: `ComputeEventHash`의 대상을 구조체 전체 임의 `json.Marshal`에 의존하지 않고, 직렬화/역직렬화 전후에 100% 동일하게 복원되는 불변 핵심 필드(PrevHash, Timestamp(RFC3339Nano), TraceID, Actor, Action, Resource, Decision, Reason, Success)의 고정 구분자(`|`) 포맷으로 못박아 모호성을 원천 제거한다.

---

## 5. 4층위 검증 범위 설계

1. **1층위 (정적 분석)**: `go vet ./...` 및 `pdp/service.go`에서 `"pdp-%d"` 형태의 즉석 `TraceID` 생성 코드가 제거되었는지 확인.
2. **2층위 (단위 검증)**:
   - `internal/audit/audit_test.go`: 연속 5개 이벤트 기록 시 1번 이벤트(`prev_hash == ""`)부터 5번 이벤트까지 체인이 정확히 연결되고 `VerifyHashChain`이 `nil`을 반환하는지 검증.
   - 파일 중간 줄 수정, 첫 줄 앞에 가짜 JSON 삽입(`{"tampered":"attack"}`), 줄 순서 변경 시 `VerifyHashChain`이 즉시 `ReasonAuditIntegrityBroken` 에러를 반환하는지 검증.
3. **3층위 (다중 프로세스·고루틴 동시성 검증)**:
   - 10개의 고루틴 및 별도 `JSONLWriter` 인스턴스가 동시에 같은 `audit.jsonl` 파일에 각 10개씩 총 100개의 이벤트를 기록한 뒤 `VerifyHashChain`을 호출했을 때 100개 전 레코드의 해시 체인이 단 한 번도 끊어지지 않음을 `go test -race`로 검증.
4. **4층위 (통합 추적성 검증)**:
   - `pep.Execute(ctx, Request{TraceID: "trace-unified-01", ...})` 실행 후 `audit.jsonl`에 기록된 `authn.verify`, `pdp.decide`, `pep.allow`/`pep.deny` 전 이벤트의 `trace_id`가 모두 `"trace-unified-01"`로 일치하고 최상위 `decision`·`reason`이 채워져 있음을 검증.

---

## 6. 10대 사전 인수 테스트 시나리오 (Acceptance Scenarios)

| ID | 테스트 시나리오 명 | 입력 조건 | 기대 결과 | 검증 포인트 |
|---|---|---|---|---|
| **TC-030-01** | 단일 이벤트 기록 시 해시 생성 | 빈 `audit.jsonl`에 첫 이벤트 기록 | `PrevHash == ""`, `CurrHash != ""` (64자 SHA-256 hex) | AP-06 해시 체인 자동 부착 확인 |
| **TC-030-02** | 연속 이벤트 해시 체인 연결 | 이벤트 E1, E2, E3 순차 기록 | `E2.PrevHash == E1.CurrHash`, `E3.PrevHash == E2.CurrHash`, `VerifyHashChain == nil` | 연쇄 해시 무결성 증명 |
| **TC-030-03** | 파일 선두/중간 변조 시 적발 | 기록된 `audit.jsonl` 첫 줄 앞에 `{"tampered":"attack"}` 삽입 후 `VerifyHashChain` 호출 | 에러 반환 (`ReasonAuditIntegrityBroken`, ExitCode `15`) | E2E-30 사후 변조 탐지 원리 완벽 작동 |
| **TC-030-04** | 레코드 내용 1바이트 수정 적발 | 2번째 이벤트의 `"deny"`를 `"allow"`로 수정 후 `VerifyHashChain` 호출 | 에러 반환 (`ReasonAuditIntegrityBroken`) | 해시 재계산 불일치 즉시 포착 |
| **TC-030-05** | 다중 `JSONLWriter` 인스턴스 교차 기록 | Writer A가 1줄 쓰고, 별도 오픈한 Writer B가 1줄 쓴 뒤 `VerifyHashChain` | Writer B가 디스크의 마지막 해시를 읽어 체인이 끊기지 않고 `VerifyHashChain == nil` | 부모·자식 별도 프로세스 간 체인 연속성 보장 |
| **TC-030-06** | 20개 고루틴 동시 기록(`-race`) | 20개 고루틴이 동시에 `Log()` 호출 후 `VerifyHashChain` | 총 20줄 파손 0건, 해시 체인 100% 유효, Data Race 0건 | `syscall.Flock` + Mutex 동시성 안전 입증 |
| **TC-030-07** | 최상위 `Decision`·`Reason` 자동 승격 | `Metadata["reason"] = "TOKEN_EXPIRED"`, `Success: false`인 이벤트 기록 | 파일에 기록된 JSON의 최상위 `decision == "deny"`, `reason == "TOKEN_EXPIRED"` | AP-04 스키마 파편화 해결 |
| **TC-030-08** | PEP → PDP 단일 `TraceID` 관통 | `pep.Request{TraceID: "trc-777"}`로 `Execute` 호출 | `authn.verify`, `pdp.decide`, `pep.allow` 모두 `trace_id == "trc-777"` | AP-05 `pdp-%d` 추적 단절 해결 |
| **TC-030-09** | PEP 거부 시 표준 `Action` 기록 | 권한 없는 파일 쓰기 요청으로 `pep.Execute` 거부 | 마지막 감사 이벤트 `action == "pep.deny"`, `decision == "deny"` | 카탈로그 `ExpectedAction`과 1:1 정합성 확보 |
| **TC-030-10** | Token Exchange 거부 시 표준 `Action` 기록 | Scope 초과 위임 요청으로 `Exchange` 거부 | 감사 이벤트 `action == "token.exchange.deny"`, `decision == "deny"`, `reason == "DELEGATION_SCOPE_EXCEEDED"` | `E2E-19`~`21` 감사 이벤트 정합성 확보 |

---

## 7. 완료 조건 (Definition of Done)

1. `internal/audit/audit.go`에 `syscall.Flock`, SHA-256 해시 체인 자동 계산, 최상위 필드 정규화, `VerifyHashChain` 구현 완료.
2. `pdp`, `pep`, `verifier`, `exchange`의 감사 이벤트가 단일 `TraceID`와 표준 최상위 `Action`/`Decision`/`Reason`을 기록하도록 정렬 완료.
3. 10대 인수 테스트(`TC-030-01` ~ `TC-030-10`) 및 `go test -race ./...` 통과.
4. 상위 대시보드([README.md](../README.md))의 `030` 단계 상태를 `Done`으로 갱신.
