# [구현지시서 010] Action·리소스 스코프 문법 확장 및 의미론적 부분집합 판정 일원화

> **문서 상태**: `Draft`
> **상위 대시보드**: [16번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [ADR 0003](../../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md)
> **선행 조건**: [로드맵 11](../../11-os-수준-격리-및-악의-워커-차단/README.md) `Done` 필수, [ADR 0003](../../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) C-2·C-3 `Accepted`
> **후속 단계**: [020_netguard_루프백_가드.md](020_netguard_루프백_가드.md)

---

## 1. 목적 및 배경

기존 `file:read`, `file:write` 액션에 더해 결정론적 로컬 가짜 도구인 `net:fetch`와 `exec:run`을 도메인 액션 및 스코프 문법(`net:fetch:<host>:<port>`, `exec:run:<allowlist-id>`)으로 확장한다.
특히 [`internal/authn/exchange/validator.go`](../../../../internal/authn/exchange/validator.go)의 `ValidateDownscope`가 단순 문자열 일치(`parentSet[cs]`)만 검사하던 한계를 보강하여, 부모의 2단 액션 스코프(예: `net:fetch`, `file:read`)가 자식의 3단 특정 리소스 스코프(예: `net:fetch:127.0.0.1:18080`, `file:read:docs/plan.txt`)를 포함하는지 판정하는 순수 함수 `domain.ScopeCovers(parentScope, childScope)`로 일원화한다 ([006번 보고서](../../../보고서/006-차기로드맵_10_16_타당성_및_단계분할_정밀검토_보고서.md) §3.7).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/domain/constants.go`, `internal/domain/error.go`: `ActionNetFetch = "net:fetch"`, `ActionExecRun = "exec:run"` 및 거부 사유 `ReasonEgressDenied = "EGRESS_DENIED"`, `ReasonExecNotAllowed = "EXEC_NOT_ALLOWED"`, `ReasonExecArgRejected = "EXEC_ARG_REJECTED"` 추가(`ExitAuthzDenied = 12` 매핑)
  - `internal/domain/scope.go`: `ScopeMatches` 확장 및 `ScopeCovers(parentScopeStr, childScopeStr string) (bool, []string)` 구현
  - `internal/authn/exchange/validator.go`: `ValidateDownscope`가 `domain.ScopeCovers`를 사용하도록 연동
  - `internal/domain/scope_test.go` 및 퍼징 시드(`FuzzScopeMatches`): 신규 스코프 문법 및 부분집합 판정 Table-Driven 테스트 추가
- **무영향**:
  - 기존 `file:read`, `file:write` 스코프의 파싱 및 매칭 결과는 100% 보존된다.

---

## 3. 세부 명세

1. **리소스 스코프 문법**:
   - `file:read:<relpath>`, `file:write:<relpath>`
   - `net:fetch:<host>:<port>` (예: `net:fetch:127.0.0.1:18080`)
   - `exec:run:<allowlist-id>` (예: `exec:run:echo-safe`)
2. **`ScopeCovers(parent, child)` 불변식**:
   - 부모가 2단 액션(`net:fetch`)을 보유하면 동일 액션의 3단 특정 타겟(`net:fetch:127.0.0.1:18080`)을 포함한다.
   - 반대로 부모가 3단 특정 타겟(`net:fetch:127.0.0.1:18080`)만 보유할 때 자식이 2단(`net:fetch`)이나 다른 포트(`net:fetch:127.0.0.1:19090`)를 요청하면 즉시 거부(`ReasonDelegationScopeExceeded`)한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | 기존 `file:read`, `file:write` 스코프 테스트 전수 실행 | 결과 100% 동일 |
| **TC-010-02** | 부모 `"net:fetch:127.0.0.1:18080"` → 자식 `"net:fetch:127.0.0.1:18080"` 교환 | 허용 |
| **TC-010-03** | 부모 `"net:fetch:127.0.0.1:18080"` → 자식 `"net:fetch:127.0.0.1:9999"` 또는 `"net:fetch"` 교환 | `ReasonDelegationScopeExceeded`(`ExitCode == 12`) 거부 |
| **TC-010-04** | `ExitCodeForReason`에 `ReasonEgressDenied`, `ReasonExecNotAllowed` 전달 | `ExitAuthzDenied(12)` 반환 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/domain -run TestScope` PASS
2. `go test -v ./internal/authn/exchange` PASS
3. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] 신규 `Action` 2종·`Reason` 3종 정의 및 `ScopeCovers` 구현 완료
- [ ] 단위·퍼징 시드 테스트 통과 후 단독 커밋
