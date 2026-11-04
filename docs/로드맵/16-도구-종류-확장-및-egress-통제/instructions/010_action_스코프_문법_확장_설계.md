# [구현지시서 010] Action·사유 도메인 확장과 액션 단일 원천

> **문서 상태**: `Draft`
> **상위 대시보드**: [16번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | [025번 보고서](../../../보고서/025-16번로드맵_구조결함_및_진행가능성_검증보고서.md) T-3·T-6·T-12·T-13
> **선행 조건**: [로드맵 15](../../15-pdp-승인-결정-ask/README.md) `Done`(충족), [ADR 0003](../../../adr/0003-차기-로드맵-범위-개정-비목표-조건부-해제.md) C-2·C-3 `Accepted`(충족)
> **후속 단계**: [020_netguard_루프백_가드.md](020_netguard_루프백_가드.md)

---

## 1. 목적 및 배경

새 도구 두 가지를 도메인 어휘로 정의하고, 지금 세 곳에 흩어진 액션 목록(PEP `NormalizeAction`, CLI `grant`, CLI `pdp`)을 `domain` 한 곳으로 모은다. 스코프 문법은 바꾸지 않는다. `net:fetch:127.0.0.1:18080`, `net:fetch:[::1]:18080`, `exec:run:echo-safe` 같은 3단 스코프는 지금 [`ScopeMatches`](../../../../internal/domain/scope.go)(34~42행, `strings.Join(parts[2:], ":")`)로 이미 맞는다. 위임 교환 검증(문자열 완전 일치)도 바꾸지 않는다(D-08).

PEP Gate 0은 이 단계에서 바꾸지 않는다. Gate 0이 새 액션을 받는 순간 Gate 2c(Jail)·Stage 5가 file 전용이라 `127.0.0.1:18080`이 상대 파일 경로로 통과하는 중간 상태가 생긴다(025번 T-3). 그래서 Gate 0의 전환은 경계 `switch`와 함께 040에서 한다. 그때까지 PEP는 새 액션을 `INVALID_ARGUMENTS`(14)로 거부한다(Fail-Closed).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - [`internal/domain/grant.go`](../../../../internal/domain/grant.go): `ActionNetFetch Action = "net:fetch"`, `ActionExecRun Action = "exec:run"`. `ParseAction(s string) (Action, error)`(앞뒤 공백 제거·소문자화, 별칭 `read`→`file:read`, `write`→`file:write`, 정식 4종만 허용), `IsValidAction(a Action) bool`(정식 4종과 정확히 같을 때만).
  - [`internal/domain/constants.go`](../../../../internal/domain/constants.go): `ReasonEgressDenied = "EGRESS_DENIED"`, `ReasonExecNotAllowed = "EXEC_NOT_ALLOWED"`, `ReasonExecArgRejected = "EXEC_ARG_REJECTED"`, `ReasonToolLimitExceeded = "TOOL_LIMIT_EXCEEDED"`.
  - [`internal/domain/error.go`](../../../../internal/domain/error.go): `ExitCodeForReason`에서 4종 → `ExitAuthzDenied`(12).
  - [`internal/cli/grant.go`](../../../../internal/cli/grant.go) 95행, [`internal/cli/pdp.go`](../../../../internal/cli/pdp.go) 95·149행: 두 값 하드코딩을 `domain.IsValidAction`으로 교체. 오류 메시지에 4종을 나열.
  - [`internal/ui`](../../../../internal/ui): 새 사유 4종의 초보자 해설(다른 사유와 같은 표에 추가).
  - [ADR 0001](../../../adr/0001-mcp-tool-call-어댑터-범위-및-프로토콜.md) 상태 줄: `Accepted (A-2 superseded in part by ADR 0003 C-3)`. ADR 0003 45행이 「16 `010` 착수 시점」으로 확정한 표기다.
- **무영향**:
  - `ScopeMatches`, `ValidateDownscope`, PDP, PEP Gate 0(이 단계에서는 file 두 가지만 통과).
  - 기존 사유의 종료 코드.

---

## 3. 세부 명세

1. **액션 단일 원천**: 액션 목록을 아는 곳은 `domain`뿐이다. `ParseAction`은 사용자 입력 해석용(별칭 허용), `IsValidAction`은 이미 정식 값이어야 하는 곳(CLI 플래그 검사, 이후 MCP·PEP)용이다.
2. **사유 4종의 의미**:
   - `EGRESS_DENIED`: URL이 루프백 리터럴이 아님, userinfo·백슬래시·비 http 스킴, allow-list에 없는 `host:port`, 리다이렉트 응답, 검증하지 않은 주소로 연결 시도.
   - `EXEC_NOT_ALLOWED`: 등록되지 않았거나 형식이 틀린 실행 ID.
   - `EXEC_ARG_REJECTED`: 인자 형식 위반(선행 `-`, 메타문자, 공백, 길이).
   - `TOOL_LIMIT_EXCEEDED`: 가드 자체의 응답·출력 바이트 상한 또는 실행 시간 상한 초과. 부모가 끊는 17과 다르다(D-06).
3. **CLI**: `grant create --action net:fetch --resource 127.0.0.1:18080`, `pdp decide --action exec:run --resource echo-safe`가 받아들여진다. 자원 형식 검사는 하지 않는다(Grant는 데이터이며, 형식 위반 자원은 Gate 0 정규화 결과와 맞지 않아 쓰이지 않는다).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-010-01** | `ParseAction`에 `"net:fetch"`, `" EXEC:RUN "`, `"read"`, `"file:write"` / `"net:post"`, `"exec"`, `""`, `"net:fetch:127.0.0.1:1"` | 앞 넷은 정식 값, 뒤 넷은 오류. `IsValidAction("read") == false` |
| **TC-010-02** | `ScopeMatches("net:fetch:[::1]:18080", "net:fetch", "[::1]:18080")`, `("exec:run:echo-safe", "exec:run", "echo-safe")`, `("net:fetch:127.0.0.1:18080", "net:fetch", "127.0.0.1:9999")` | true, true, false (현행 코드 회귀 고정) |
| **TC-010-03** | 부모 스코프 `"file:read"` → 자식 `"file:read:docs/a.txt"` 교환, 부모 `"net:fetch:127.0.0.1:18080"` → 자식 `"net:fetch"` 교환 | 둘 다 `DELEGATION_SCOPE_EXCEEDED`(12). 교환 검증 불변(D-08) |
| **TC-010-04** | `ExitCodeForReason`에 새 사유 4종 | 모두 12 |
| **TC-010-05** | PEP에 `Action: "net:fetch"` 요청 | Gate 0 `INVALID_ARGUMENTS`(14), Gate 2c·Stage 5 미도달(040 전 중간 상태 Fail-Closed) |
| **TC-010-06** | `grant create --action net:fetch --resource 127.0.0.1:18080`, `--action net:post` | 앞은 생성 성공, 뒤는 14 |

---

## 5. 4층위 검증 기준

1. `go test ./internal/domain ./internal/cli ./internal/authn/exchange ./internal/authz/pep` PASS
2. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] Action 2종·`ParseAction`·`IsValidAction`·Reason 4종(12) 정의
- [ ] CLI `grant`·`pdp` 하드코딩 제거, ui 해설 추가
- [ ] ADR 0001 상태 줄 표기
- [ ] 테스트 통과 후 변경 파일만 단독 커밋
