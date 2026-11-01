# 030. 순수 결정 엔진 PDP 및 CLI 시뮬레이션 구현지시서

> **상태**: `Done`
> **선행 조건**: 020 (PAP 정책 관리 및 PIP 실시간 상태 공급 구현) 완료 (`c1e4961`)
> **상위 대시보드**: [README.md](../README.md) | **마스터 설계**: [ROADMAP.md](../ROADMAP.md)

---

## 1. 목적 (Context & Why)

본 지시서는 NIST SP 800-162 표준 인가 아키텍처의 핵심 판정 심장부인 **순수 정책 결정점(Policy Decision Point, PDP)**을 구축하고, 실시간 권한 회수 및 Security Epoch 무효화 동작을 누구나 직관적으로 검증할 수 있는 **CLI 시뮬레이션(`pdp decide`, `pdp explain`)**을 완성하는 작업이다.

1. **순수 함수 결정 엔진 (`internal/authz/pdp`)**:
   - 파일 I/O(`os`, `path/filepath`), 네트워크, 암호키 접근 등 일체의 사이드 이펙트(부작용) 의존성이 **0%**인 순수 결정 함수를 구현한다.
   - 오직 요청 속성(주체, 액션, 리소스, 제시된 Epoch)과 PIP가 제공한 상태 스냅샷(`SubjectSnapshot`)만을 대조하여 `(ALLOW|DENY, Reason, Metadata)`를 결정론적(Deterministic)으로 도출한다.
2. **실시간 회수 및 Epoch 기반 무효화 증명**:
   - 주체별 Security Epoch 불일치(`token.epoch != pip.current_epoch`) 시 `SUBJECT_EPOCH_REVOKED`로 최우선 차단한다.
   - 유효한 활성 Grant가 없을 경우 `NO_ACTIVE_GRANT`, 이전에 존재했으나 회수(Revoked)된 Grant인 경우 `GRANT_REVOKED`를 정확히 구별하여 반환한다.
3. **초보자 배려 3단 설명 가능성(Explainability UX)**:
   - `authz-harness pdp decide`: 기계 및 자동화 하네스가 판정 결과와 표준 종료 코드(`0`, `12`)를 즉각 확인할 수 있는 표준 명령.
   - `authz-harness pdp explain`: 6단계 관문 진행 표시기, 세부 매칭 테이블, 그리고 "인가 거부는 시스템 오류가 아니라 의도된 보안 방어 성공"임을 명시하는 부정 테스트 역설 해소 박스를 시각적 터미널 UI로 출력한다.
4. **감사 추적 연동 (Tri-Separation)**:
   - 모든 결정 이벤트는 `internal/audit.Writer`를 통해 `audit.jsonl`에 해시 체인으로 기록되며, 운영 디버그 로그는 `stderr`로, 사용자 UI는 `stdout`으로 엄격히 분리된다.

---

## 2. 패키지 배치 및 6계층 DAG 구조

```text
Layer 5:  [cmd/authz-harness] / [internal/cli]  (CLI pdp decide/explain)
             │                     │
             v (상태 조회)          v (인가 결정 요청)
Layer 2B: [internal/authz/pip] ──> [internal/authz/pdp] (Pure Decision Engine)
             │                     │ (NO os/filepath, NO jail!)
             │                     │
             │                     v (결정 감사 기록)
Layer 1:     │                  [internal/audit] (JSONLWriter)
             │                     │
             v                     v
Layer 0:  [internal/domain] (Reason, Action, ExitCode, Epoch, Grant)
```

- **계층 분리 및 아키텍처 불변식 (D-02, AP-03)**:
  - `internal/authz/pdp` 패키지는 OS 파일 시스템(`os`, `io/fs`, `path/filepath`)이나 Layer 2C(`internal/jail`)를 **절대 import하지 않는다**.
  - PDP 내부의 평가 로직은 외부 상태를 직접 조회하지 않으며, 오직 인자로 전달된 불변 스냅샷(`pip.SubjectSnapshot`)에만 기반한다.
  - 모든 디스크 읽기 I/O는 Layer 2B의 `internal/authz/pip`가 전담하고, 감사는 Layer 1의 `internal/audit`가 전담한다.

---

## 3. 세부 설계 및 인터페이스 정의

### 3.1 PDP 도메인 모델 및 순수 평가 엔진 (`internal/authz/pdp`)

```go
package pdp

import (
    "authz-harness/internal/authz/pip"
    "authz-harness/internal/domain"
)

// DecisionType 은 인가 판정의 최종 결과(허용/거부)다.
type DecisionType string

const (
    DecisionAllow DecisionType = "ALLOW"
    DecisionDeny  DecisionType = "DENY"
)

// Request 는 PDP 인가 결정을 위한 단일 요청 명세다.
type Request struct {
    Subject  string        `json:"subject"`
    Action   domain.Action `json:"action"`
    Resource string        `json:"resource"`
    Epoch    domain.Epoch  `json:"epoch"` // 요청자가 제시한 Security Epoch (기본값 1)
}

// Decision 은 PDP의 판정 결과 및 상세 사유다.
type Decision struct {
    Decision DecisionType  `json:"decision"`
    Reason   domain.Reason `json:"reason"`
    GrantID  string        `json:"grant_id,omitempty"`
    Details  string        `json:"details,omitempty"`
}

// Evaluate 는 일체의 부작용 없이 순수 인자만을 대조하여 인가 여부를 결정하는 순수 함수다.
func Evaluate(req Request, snapshot *pip.SubjectSnapshot) Decision
```

#### 판정 알고리즘 우선순위 (Decision Precedence)
1. **입력 무결성 검증**: `req.Subject`, `req.Action`, `req.Resource`가 비어있거나 `req.Epoch < 1`인 경우 `DENY (NO_ACTIVE_GRANT)` 또는 `INVALID_TOKEN`.
2. **Security Epoch 일치 검증**: `req.Epoch != snapshot.CurrentEpoch`인 경우 즉시 **`DENY (ReasonSubjectEpochRevoked)`** 반환 (최우선 차단).
3. **활성 Grant 매칭 검증**:
   - `snapshot.ActiveGrants` 중 `g.Action == req.Action && g.Resource == req.Resource`를 만족하는 레코드가 존재하면 즉시 **`ALLOW (ReasonAuthorized)`** 반환 (해당 `g.ID` 포함).
4. **회수된 Grant 이력 검증**:
   - 활성 Grant는 없으나 `snapshot.RevokedGrants` 중 `g.Action == req.Action && g.Resource == req.Resource`를 만족하는 레코드가 존재하면 즉시 **`DENY (ReasonGrantRevoked)`** 반환.
5. **기본 거부 (Deny-by-Default / Fail-Closed)**:
   - 위 조건에 부합하지 않는 모든 요청은 **`DENY (ReasonNoActiveGrant)`** 반환.

### 3.2 PDP 서비스 인터페이스 (`Decider`) 및 PIP/Audit 연동

```go
package pdp

import (
    "context"
    "authz-harness/internal/audit"
    "authz-harness/internal/authz/pip"
)

// Service 는 PIP 상태 조회와 감사 로깅을 조율하는 PDP 서비스 규약이다.
type Service interface {
    Decide(ctx context.Context, req Request) (*Decision, error)
}

// pdpService 는 Service의 표준 구현체다.
type pdpService struct {
    pipSvc pip.Service
    audit  audit.Writer
}

func NewService(pipSvc pip.Service, audit audit.Writer) Service
```

- **감사 이벤트 매핑 (`internal/audit.Event`)**:
  - `action`: `"pdp.decide"`
  - `actor`: `req.Subject`
  - `resource`: `req.Resource`
  - `success`: `decision.Decision == DecisionAllow`
  - `metadata`:
    ```json
    {
      "decision": "ALLOW" | "DENY",
      "reason": "AUTHORIZED" | "NO_ACTIVE_GRANT" | "GRANT_REVOKED" | "SUBJECT_EPOCH_REVOKED",
      "subject": req.Subject,
      "requested_action": string(req.Action),
      "requested_epoch": int64(req.Epoch),
      "current_epoch": int64(snapshot.CurrentEpoch),
      "grant_id": decision.GrantID
    }
    ```

### 3.3 PIP `SubjectSnapshot` 보강 (`internal/authz/pip`)

회수된 Grant로 인한 거부(`GRANT_REVOKED`)와 아예 권한이 없던 거부(`NO_ACTIVE_GRANT`)를 PDP가 정확히 구별할 수 있도록, PIP 스냅샷에 `RevokedGrants` 목록을 보강한다.

```go
type SubjectSnapshot struct {
    Subject       string         `json:"subject"`
    CurrentEpoch  domain.Epoch   `json:"current_epoch"`
    ActiveGrants  []domain.Grant `json:"active_grants"`
    RevokedGrants []domain.Grant `json:"revoked_grants,omitempty"`
    Timestamp     time.Time      `json:"timestamp"`
}
```

### 3.4 CLI 서브커맨드 UX 설계 (`cmd/authz-harness`, `internal/cli`)

#### 1. 인가 결정 질의 (`pdp decide`)
```bash
# 기본 사용법
authz-harness pdp decide --sub worker-01 --action file:read --resource docs/plan.txt [--epoch 1]

# 1) 허용 시 (ALLOW)
# stdout:
[DECISION: ALLOW] Subject: worker-01 | Action: file:read | Resource: docs/plan.txt | Reason: AUTHORIZED | GrantID: grant-abc12345
# exit code: 0 (EXIT_SUCCESS)

# 2) 거부 시 (DENY)
# stdout:
[DECISION: DENY] Subject: worker-01 | Action: file:read | Resource: docs/plan.txt | Reason: GRANT_REVOKED
# exit code: 12 (EXIT_AUTHZ_DENIED)
```

#### 2. 초보자 친화적 설명 뷰 (`pdp explain`)
```bash
authz-harness pdp explain --sub worker-01 --action file:read --resource docs/plan.txt [--epoch 1]

# stdout 출력 예시:
================================================================================
                    AUTHZ PIPELINE VERIFICATION REPORT
================================================================================
 [1. AuthN & Signature]    : [PASS] (Simulated Context)
 [2. Token Temporal Claims]: [PASS] (Simulated Context)
 [3. Token Scope Match]    : [PASS] (Scope covers file:read)
 [4. PDP Real-Time Engine] : [FAIL] Reason: GRANT_REVOKED
 [5. PEP & Jail Boundary]  : [SKIP] (Halted before file I/O)
 [6. Audit Trace Evidence] : [PASS] Recorded to audit.jsonl
--------------------------------------------------------------------------------
 REQUEST CONTEXT:
  - Subject         : worker-01
  - Action          : file:read
  - Resource        : docs/plan.txt
  - Presented Epoch : 1
  - Current Epoch   : 1
--------------------------------------------------------------------------------
 PDP EVALUATION RESULT:
  - Final Decision  : DENY
  - Primary Reason  : GRANT_REVOKED
  - Matched Grant   : grant-abc12345 (Revoked at 2026-11-01T18:30:00Z)
  - Detail Message  : 요청된 권한이 이전에 발급되었으나 명시적으로 회수(Revoked)되었습니다.
--------------------------------------------------------------------------------
 [안내: 부정 테스트 역설 해소 (Negative Test Resolution)]
  * 본 인가 거부(DENY)는 하네스/엔진 오류가 아니라, 미인가 접근 시도를 성공적으로 차단한 정상 방어 결과입니다.
================================================================================
# exit code: 0 (설명 뷰는 조회를 위해 정상 0 종료)
```

---

## 4. 파급 범위와 무영향 근거 증명 (Impact Scope & Zero-Impact Proof)

1. **추가 및 변경 컴포넌트**:
   - `internal/authz/pdp`: 순수 인가 결정 로직, 결정 도메인 모델, 서비스 구현체, 단위 테스트 신규 생성.
   - `internal/authz/pip`: `SubjectSnapshot`에 `RevokedGrants` 필드 추가 및 `GetSubjectSnapshot`에서 회수 목록 수집 로직 보강.
   - `cmd/authz-harness/main.go` & `internal/cli/pdp.go`: `pdp` 서브커맨드 라우터 및 `decide`/`explain` 러너 신규 배선.
2. **무영향 컴포넌트 (Zero-Impact Proof)**:
   - `internal/authz/pap`: 이미 완성된 정책 관리점은 이번 PDP 구현으로 인해 어떠한 수정도 필요 없음.
   - `internal/authz/state`: Zone B `FileStore`는 기존 규약 그대로 유지됨.
   - `internal/audit`: 기존 `audit.Writer` 인터페이스를 그대로 주입받아 호출하므로 감사 저장소 무영향.
   - `internal/domain`: `ReasonAuthorized`, `ReasonNoActiveGrant`, `ReasonGrantRevoked`, `ReasonSubjectEpochRevoked` 및 `ExitAuthzDenied(12)`가 이미 정의되어 있어 도메인 상수 추가나 변경 불필요.

---

## 5. 사전 점검 및 실패 위험 분석 (Pre-Mortem)

1. **위험: PDP 패키지에 OS 파일 시스템 또는 경로 정규화 패키지가 침투하여 순수성 오염 (AP-03)**
   - *원인*: 개발 편의상 PDP 안에서 파일 존재 여부를 체크하려 하거나 `path/filepath`를 호출함.
   - *방어책*: `internal/authz/pdp/pdp_test.go`에 정적 의존성 검사 테스트(`TestPDP_StrictNoOSImports`)를 포함하여, `os`, `path/filepath`, `internal/jail`을 import할 경우 단위 테스트가 컴파일/실행 단계에서 즉시 실패하도록 강제.
2. **위험: Epoch 증가 후 이전 Epoch를 가진 요청이 우회 허용되는 결함**
   - *원인*: Grant 매칭 로직을 Epoch 검증보다 먼저 실행하여 회수된 세대의 토큰이 허용됨.
   - *방어책*: `Evaluate` 함수의 최상단에서 `req.Epoch != snapshot.CurrentEpoch` 조건을 단 1순위로 평가하여 즉각 거부하도록 알고리즘 고정.
3. **위험: 다중 프로세스에서 PDP 실행 시 감사 로그 손상**
   - *원인*: 여러 CLI 프로세스가 동시에 `pdp decide`를 실행하여 `audit.jsonl`에 동시 쓰기를 시도함.
   - *방어책*: 000 및 010 단계에서 검증된 `audit.JSONLWriter`의 `flock` 기반 원자적 append를 그대로 사용하여 파일 무결성을 100% 보장.

---

## 6. 4층위 검증 범위 설계

1. **1층위 (자동화 스크립트)**:
   - `scripts/run_lint.sh` 실행 및 Go 정적 분석 통과.
   - PDP 패키지의 외부 의존성 정적 검사 통과.
2. **2층위 (단위 및 구조 검증)**:
   - `internal/authz/pdp/pdp_test.go`:
     - L1 결정표 Table-Driven 테스트 (정상 허용, Grant 없음 거부, Grant 회수 거부, Epoch 불일치 거부, 액션 불일치, 리소스 불일치, 타 주체 Grant 격리).
     - 감사 기록 실패 시 Fail-Closed 에러 전파 단위 테스트.
   - `internal/authz/pip/pip_test.go`:
     - `RevokedGrants` 수집 동작 검증 단위 테스트.
3. **3층위 (상태 및 정합성 검증)**:
   - `pdp decide` 실행 후 `audit.jsonl`에 `action: "pdp.decide"` 이벤트가 기록되고 해시 체인 무결성이 유지되는지 검증.
4. **4층위 (CLI 인수 검증)**:
   - `authz-harness pdp decide` 및 `pdp explain`을 실제 실행하여 stdout 포맷, 설명 뷰 출력, 기대 종료 코드(`0`, `12`, `14`) 검증.

---

## 7. 사전 인수 테스트 시나리오 (Acceptance Scenarios)

### 시나리오 1: Grant 없을 때 거부 (NO_ACTIVE_GRANT)
- **입력 (Given/When)**:
  - `authz-harness pdp decide --sub worker-01 --action file:read --resource docs/plan.txt`
- **기대 결과 (Then)**:
  - stdout: `[DECISION: DENY] Subject: worker-01 | Action: file:read | Resource: docs/plan.txt | Reason: NO_ACTIVE_GRANT`
  - 종료 코드: `12` (`EXIT_AUTHZ_DENIED`)
  - `audit.jsonl`에 `action: "pdp.decide"`, `success: false`, `reason: "NO_ACTIVE_GRANT"` 기록 확인.

### 시나리오 2: Grant 발급 후 정상 허용 (AUTHORIZED)
- **입력 (Given/When)**:
  - `authz-harness grant create --sub worker-01 --action file:read --resource docs/plan.txt`
  - `authz-harness pdp decide --sub worker-01 --action file:read --resource docs/plan.txt`
- **기대 결과 (Then)**:
  - stdout: `[DECISION: ALLOW] Subject: worker-01 | Action: file:read | Resource: docs/plan.txt | Reason: AUTHORIZED | GrantID: grant-...`
  - 종료 코드: `0` (`EXIT_SUCCESS`)
  - `audit.jsonl`에 `action: "pdp.decide"`, `success: true`, `reason: "AUTHORIZED"` 기록 확인.

### 시나리오 3: Grant 회수 후 즉시 실시간 거부 (GRANT_REVOKED)
- **입력 (Given/When)**:
  - `authz-harness grant revoke --id <grant_id>`
  - 동일 질의 재실행: `authz-harness pdp decide --sub worker-01 --action file:read --resource docs/plan.txt`
- **기대 결과 (Then)**:
  - stdout: `[DECISION: DENY] Subject: worker-01 | Action: file:read | Resource: docs/plan.txt | Reason: GRANT_REVOKED`
  - 종료 코드: `12` (`EXIT_AUTHZ_DENIED`)
  - `audit.jsonl`에 `action: "pdp.decide"`, `success: false`, `reason: "GRANT_REVOKED"` 기록 확인.

### 시나리오 4: Security Epoch 증가 후 즉시 일괄 무효화 (SUBJECT_EPOCH_REVOKED)
- **입력 (Given/When)**:
  - `authz-harness grant create --sub worker-02 --action file:write --resource data/out.txt`
  - `authz-harness grant bump-epoch --sub worker-02` (Epoch 1 -> 2로 증가)
  - 이전 Epoch(1) 질의 실행: `authz-harness pdp decide --sub worker-02 --action file:write --resource data/out.txt --epoch 1`
- **기대 결과 (Then)**:
  - stdout: `[DECISION: DENY] Subject: worker-02 | Action: file:write | Resource: data/out.txt | Reason: SUBJECT_EPOCH_REVOKED`
  - 종료 코드: `12` (`EXIT_AUTHZ_DENIED`)
  - `audit.jsonl`에 `action: "pdp.decide"`, `success: false`, `reason: "SUBJECT_EPOCH_REVOKED"` 기록 확인.

### 시나리오 5: 초보자 친화적 관측 뷰 (`pdp explain`)
- **입력 (Given/When)**:
  - `authz-harness pdp explain --sub worker-01 --action file:read --resource docs/plan.txt`
- **기대 결과 (Then)**:
  - stdout: 6단계 관문 진행 표시기, 요청 컨텍스트, 상세 판정 사유, 부정 테스트 역설 해소 박스 정상 출력.
  - 종료 코드: `0` (`EXIT_SUCCESS`).

### 시나리오 6: 필수 인자 누락 시 입력 오류
- **입력 (Given/When)**:
  - `authz-harness pdp decide --sub worker-01` (action, resource 누락)
- **기대 결과 (Then)**:
  - stderr: 에러 안내 문구 출력
  - 종료 코드: `14` (`EXIT_BAD_INPUT`)

---

## 8. 완료 조건 (Definition of Done)

- [x] `internal/authz/pip/service.go`에 `RevokedGrants` 수집 지원 반영
- [x] `internal/authz/pdp/service.go` (순수 평가 함수 `Evaluate` 및 `Service` 구현체) 작성 완료
- [x] `internal/authz/pdp/pdp_test.go` 작성 완료:
  - [x] 순수 L1 결정표 Table-Driven 테스트 100% 통과
  - [x] `os`, `path/filepath`, `internal/jail` 미사용 정적 의존성 검증 통과
- [x] `internal/cli/pdp.go` 및 `internal/cli/pdp_test.go` 작성 완료 (`decide`, `explain`)
- [x] `cmd/authz-harness/main.go`에 `pdp` 서브커맨드 배선 완료
- [x] `go test -race -v ./internal/authz/pdp/... ./internal/authz/pip/... ./internal/cli/...` 100% 통과
- [x] Pre-commit 보안 스캔(`public_safety_scan.py`, `gitleaks`) 통과
- [x] 대시보드([README.md](../README.md)) 030 상태 및 실행 기록 갱신
