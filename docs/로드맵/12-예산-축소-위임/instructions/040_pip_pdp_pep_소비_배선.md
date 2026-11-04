# [구현지시서 040] PEP 예산 차감·환급 배선

> **문서 상태**: `Done` (2026-11-04)
> **상위 대시보드**: [12번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | 교정 근거: [021번 보고서](../../../보고서/021-12번로드맵_구조결함_및_진행가능성_검증보고서.md) B-5·B-7
> **선행 조건**: [030_교환_서비스_단조_축소_검증.md](030_교환_서비스_단조_축소_검증.md) 완료
> **후속 단계**: [050_g11_e2e_시나리오.md](050_g11_e2e_시나리오.md)

> 파일명은 이전 설계(PIP/PDP/PEP 배선)의 이름을 링크 보존을 위해 유지한다. 교정 후 이 단계는 **PEP만** 바꾼다.

---

## 1. 목적 및 배경

예산 집행은 PEP 한 곳에서 원장 `Consume`으로 원자적으로 한다. PDP·PIP는 예산을 보지 않는다. 상태를 소비하는 Replay 원장이 Gate 1에서 원자 소비로 집행되는 것과 같은 원칙이다. PDP 스냅샷 사전 검사는 잠금 밖에서 읽으므로 권위가 없고, 같은 거부를 두 곳에서 다른 단계 이름으로 내게 되므로 두지 않는다.

지켜야 할 불변식:
- PDP 순수성(`TC-060-01`): PDP를 건드리지 않으므로 자동 보존.
- `Gateway.Execute` 단일 `return`(`TC-060-04`): 새 단계와 환급은 모두 `runPipeline` 안에 둔다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pep/gateway.go`:
    - `Config`에 `BudgetLedger budget.Ledger`(선택) 추가. PEP는 이미 `internal/authn/token`을 import하므로 같은 계층(Layer 2A)의 `internal/authn/budget` import는 새 방향의 의존이 아니다.
    - 단계 상수 `StageBudget Stage = "stage3b_budget"` 추가.
    - `pipelineState`에 예산 토큰 여부·차감 기록(환급용) 필드 추가.
  - `internal/app/builder.go`: `pep.Config.BudgetLedger = AppStack.BudgetLedger` 주입. `VerifyOnly` 워커도 원장을 받는다(워커가 소비 주체이므로).
  - `internal/authz/pep/budget_test.go` [신규]
  - `internal/ui/pipeline.go`: 새 단계 `stage3b_budget` 표시명 추가(표시가 단계 문자열에 의존하는 경우에만).
- **변경하지 않음**: `internal/authz/pdp`, `internal/authz/pip`, `pip.SubjectSnapshot`, `pdp.Request`.
- **무영향**: `Budget == nil` 토큰은 새 단계를 그대로 통과(아무것도 하지 않음)한다. 기존 `E2E-01`~`E2E-49` 영향 없음.

---

## 3. 세부 명세 — `runPipeline` 안의 순서

[`pep/gateway.go`](../../../../internal/authz/pep/gateway.go)의 현재 순서는 Gate 0 → Gate 1 → Gate 2(PDP) → Gate 2c(Jail) → Stage 4(사전 감사) → Stage 5(I/O)다.

1. **Gate 1 이후**: `verifiedClaims.Claims.Budget != nil`이면 예산 토큰으로 표시한다. 예산 토큰인데 `g.cfg.BudgetLedger == nil`이면 Gate 1 단계에서 `ReasonInternalError`(16)로 거부한다(Fail-Closed).
2. **`StageBudget` (Gate 2c 뒤, Stage 4 앞)** — 쓰기만:
   - `file:write`이면 `Consume(jti, 1, 0, int64(len(req.Data)))`. 실패하면 원장이 준 사유(`BUDGET_EXHAUSTED`, 손상 시 `INTERNAL_ERROR`)로 거부. 파일은 한 바이트도 쓰이지 않고, Stage 4 「사전 감사 통과」 기록도 남지 않는다.
   - 성공하면 차감량을 `state`에 기록하고 지연 환급을 건다: `runPipeline`에서 이후 단계가 에러를 반환하면 `Refund(jti, 1, 0, len)`을 호출한다(이름 있는 반환값 + `defer`, 또는 이후 단계 실패 지점에서 `state` 기반 헬퍼 호출). 환급 실패는 운영 로그에 남기고 원래 거부 사유는 바꾸지 않는다.
   - `file:read`는 이 단계에서 아무것도 하지 않는다(읽기 전에는 바이트 수를 모른다).
3. **Stage 4 실패**(`InjectAuditFailure` 포함) 또는 **Stage 5 쓰기 실패** → 2의 환급이 실행된다.
4. **Stage 5 읽기**: `Jail.ReadFile` 성공 직후 `Consume(jti, 1, int64(len(data)), 0)`. 실패하면 `data`를 결과에 담지 않고 버린 뒤 원장 사유로 거부한다(`Result.Data` 비어 있음). 이 경우 Stage 4 사전 감사 기록 뒤에 거부 감사가 따라붙는다 — 읽기는 부작용이 없으므로 허용하며, 테스트로 순서를 고정한다.
5. 거부 감사·종료 코드는 기존 `finalize`가 처리한다. `Execute`는 바꾸지 않는다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `MaxCalls: 1` 루트 예산 토큰으로 `Execute`(read) 2회 | 1회차 `ExitSuccess(0)`, 2회차 `ExitAuthzDenied(12)` + `BUDGET_EXHAUSTED` (`TOKEN_REPLAY_DETECTED` 아님) |
| **TC-040-02** | `MaxCalls: 5, MaxWriteBytes: 10`으로 11바이트 `file:write` | `12` + `BUDGET_EXHAUSTED`, 실패 단계 `stage3b_budget`, 대상 파일 미생성, 원장 잔량 변화 없음 |
| **TC-040-03** | `MaxCalls: 5, MaxReadBytes: 5`로 20바이트 파일 `file:read` | `12` + `BUDGET_EXHAUSTED`, `len(res.Data) == 0` |
| **TC-040-04** | `MaxCalls: 5, MaxWriteBytes: 10`, `InjectAuditFailure: true`로 5바이트 쓰기 | 감사 실패 거부, 원장 잔량 `Calls 5 / Write 10` 그대로(환급 확인), 파일 무변화 |
| **TC-040-05** | 원장에 엔트리가 없는 예산 토큰(예: 교환 예약 실패 후 남은 토큰을 흉내)으로 read | `12` + `BUDGET_EXHAUSTED` |
| **TC-040-06** | `BudgetLedger` 없이 만든 PEP에 예산 토큰 | `16` 거부 |
| **TC-040-07** | `Budget == nil` 토큰으로 read 2회 | 기존과 같게 2회차 `TOKEN_REPLAY_DETECTED(11)` |
| **TC-040-08** | `TestArchitectureGuardrails` (`TC-060-01`, `TC-060-04`, `TC-081-01`) | 모두 PASS |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pep -run TestBudget` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test -race ./internal/authz/... ./internal/app` 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [x] `StageBudget`(쓰기 사전 차감)·지연 환급·읽기 사후 차감·원장 부재 Fail-Closed 구현
- [x] `BuildStack`에서 PEP에 원장 주입(워커 포함)
- [x] `TC-060-01`·`TC-060-04`·`TC-081-01` 통과, 대시보드 갱신 및 단독 커밋
