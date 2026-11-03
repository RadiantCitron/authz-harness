# [구현지시서 010] Action·리소스 스코프 문법 확장 및 의미론적 부분집합 판정 일원화

> **문서 상태**: `Draft`
> **상위 대시보드**: [16번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0003](../../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md)
> **선행 조건**: [로드맵 11](../../11-os-수준-격리-및-악의-워커-차단/README.md) `Done` 필수, [ADR 0003](../../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) C-2·C-3 `Accepted`
> **후속 단계**: [020_netguard_루프백_가드.md](020_netguard_루프백_가드.md)

---

## 1. 목적 및 배경

기존 `file:read`, `file:write` 액션에 더해 결정론적 로컬 가짜 도구인 `net:fetch`와 `exec:run`을 도메인 액션 및 스코프 문법(`net:fetch:<host>:<port>`, `exec:run:<allowlist-id>`)으로 확장한다.
특히 두 가지 기존 코드 한계를 함께 해소한다:
1. [`internal/authn/exchange/validator.go`](../../../../internal/authn/exchange/validator.go)의 `ValidateDownscope`가 단순 문자열 일치(`parentSet[cs]`)만 검사하던 한계를 보강하여, 부모의 2단 액션 스코프(예: `net:fetch`, `file:read`)가 자식의 3단 특정 리소스 스코프(예: `net:fetch:127.0.0.1:18080`, `file:read:docs/plan.txt`)를 포함하는지 판정하는 순수 함수 `domain.ScopeCovers(parentScope, childScope)`로 일원화한다 ([006번 보고서](../../../보고서/006-차기로드맵_10_16_타당성_및_단계분할_정밀검토_보고서.md) §3.7).
2. [`internal/cli/grant.go:93`](../../../../internal/cli/grant.go) 및 [`internal/cli/pdp.go:95,149`](../../../../internal/cli/pdp.go)에서 `action != ActionFileRead && action != ActionFileWrite`로 하드코딩된 액션 검증을 `domain.IsValidAction(action)`으로 일원화한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/domain/constants.go`, `internal/domain/error.go`, `internal/domain/grant.go`:
    - `ActionNetFetch Action = "net:fetch"`, `ActionExecRun Action = "exec:run"` 및 `IsValidAction(a Action) bool` 헬퍼 추가
    - 거부 사유 `ReasonEgressDenied = "EGRESS_DENIED"`, `ReasonExecNotAllowed = "EXEC_NOT_ALLOWED"`, `ReasonExecArgRejected = "EXEC_ARG_REJECTED"` 추가 및 `ExitCodeForReason`에서 `ExitAuthzDenied(12)` 매핑
  - `internal/domain/scope.go`: `ScopeMatches` 확장(IPv6 `[::1]:18080` 등 콜론이 여러 개인 3단 이상 타겟도 `parts[0]+":"+parts[1]` 액션과 `strings.Join(parts[2:], ":")` 타겟으로 정확히 분리) 및 `ScopeCovers(parentScopeStr, childScopeStr string) (bool, []string)` 구현
  - `internal/authn/exchange/validator.go`: `ValidateDownscope`가 단순 `parentSet[cs]` 대신 `domain.ScopeCovers(parentClaims.Scope, requestedScope)`를 사용하도록 연동
  - `internal/cli/grant.go`, `internal/cli/pdp.go`: 하드코딩된 2종 액션 검사를 `domain.IsValidAction(action)`으로 교체하여 CLI에서도 `net:fetch`, `exec:run` Grant 생성·판정 지원
  - `internal/domain/scope_test.go` 및 퍼징 시드(`FuzzScopeMatches`): 신규 스코프 문법 및 부분집합 판정 Table-Driven 테스트 추가
- **무영향**:
  - 기존 `file:read`, `file:write` 스코프의 파싱 및 매칭 결과는 100% 보존된다.

---

## 3. 세부 명세

1. **리소스 스코프 문법**:
   - `file:read:<relpath>`, `file:write:<relpath>`
   - `net:fetch:<host>:<port>` (예: `net:fetch:127.0.0.1:18080`, `net:fetch:[::1]:18080`)
   - `exec:run:<allowlist-id>` (예: `exec:run:echo-safe`)
2. **`ScopeCovers(parentScopeStr, childScopeStr string) (bool, []string)` 불변식**:
   - 각 자식 스코프 토큰 `cs`에 대해 부모 스코프 토큰 `ps` 중 하나라도 다음을 만족하면 포함(`covered`)으로 판정한다:
     - `ps == cs` (완전 일치)
     - `ps`가 유효한 2단 액션(`file:read`, `file:write`, `net:fetch`, `exec:run`)이고, `cs`가 `ps + ":"` 접두사로 시작하며 타겟 부분이 비어 있지 않고 `..`나 `*`를 포함하지 않을 때 (`net:fetch` ⊇ `net:fetch:127.0.0.1:18080`).
   - 반대로 부모가 3단 특정 타겟(`net:fetch:127.0.0.1:18080`)만 보유할 때 자식이 2단(`net:fetch`)이나 다른 포트(`net:fetch:127.0.0.1:19090`)를 요청하면 미포함으로 판정하여 `ReasonDelegationScopeExceeded`(`12`)를 반환한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | 기존 `file:read`, `file:write` 스코프 테스트 전수 실행 | 결과 100% 동일 |
| **TC-010-02** | 부모 `"net:fetch"` → 자식 `"net:fetch:127.0.0.1:18080"` 교환 및 `"net:fetch:127.0.0.1:18080"` → 동일 스코프 교환 | 허용 |
| **TC-010-03** | 부모 `"net:fetch:127.0.0.1:18080"` → 자식 `"net:fetch:127.0.0.1:9999"` 또는 `"net:fetch"` 교환 | `ReasonDelegationScopeExceeded`(`ExitCode == 12`) 거부 |
| **TC-010-04** | `ExitCodeForReason`에 `ReasonEgressDenied`, `ReasonExecNotAllowed`, `ReasonExecArgRejected` 전달 | 모두 `ExitAuthzDenied(12)` 반환 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/domain -run TestScope` PASS
2. `go test -v ./internal/authn/exchange ./internal/cli` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] 신규 `Action` 2종·`IsValidAction`·`Reason` 3종 정의 및 `ScopeCovers` 구현 완료
- [ ] `exchange/validator.go` 및 `cli/grant.go`·`pdp.go` 연동 완료
- [ ] 단위·퍼징 시드 테스트 통과 후 단독 커밋
