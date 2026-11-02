# [구현지시서 040] PIP/PDP/PEP 예산 소비·정산 배선 (SESE 및 PDP 순수성 보존)

> **문서 상태**: `Draft`
> **상위 대시보드**: [12번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_교환_서비스_단조_축소_검증.md](030_교환_서비스_단조_축소_검증.md) 완료
> **후속 단계**: [050_g11_e2e_시나리오.md](050_g11_e2e_시나리오.md)

---

## 1. 목적 및 배경

서브에이전트 워커가 도구를 실행할 때 PIP가 잔여 예산을 조회해 공급하고, PDP가 순수 함수로 예산 충분 여부를 1차 판정한 뒤, PEP가 파일 I/O 직전에 원자적으로 예산을 차감·정산하도록 배선한다.
이 과정에서 **① PDP의 파일/원장 무의존성(`TC-060-01`)**과 **② PEP `Gateway.Execute`의 단일 출구(`TC-060-04`, `return g.finalize(...)` 단 1개)** 불변식을 100% 보존한다 ([006번 보고서](../../../보고서/006-차기로드맵_10_16_타당성_및_단계분할_정밀검토_보고서.md) §3.3).

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/pip/service.go`: `DecisionEnvironment`에 `RemainingBudget *domain.Budget` 공급 필드 추가
  - `internal/authz/pdp/service.go`: 토큰에 `Budget != nil`이 있을 때 요청 액션(`file:read`/`file:write`)과 데이터 크기를 `RemainingBudget`과 비교하여 부족 시 `ReasonBudgetExhausted` 거부 반환 (파일 I/O 일절 없음)
  - `internal/authz/pep/gateway.go`: `runPipeline` 내부에서 Stage 4(사전 감사) 직전에 원장 원자 차감(`Consume`)을 수행하고, Stage 5 I/O 실패 시 `finalize`에서 차감분을 환급(`Refund`)하도록 배선 (`Execute` 함수 내 `return` 문 1개 유지)
  - `internal/app/builder.go`: `AppStack`에 `BudgetLedger` 조립 연결
- **무영향**:
  - `Budget == nil`인 토큰은 PIP/PDP/PEP 예산 차감 단계를 그대로 통과하므로 기존 시나리오에 영향을 주지 않는다.

---

## 3. 세부 명세

1. **PDP 순수 판정 (`internal/authz/pdp/service.go`)**:
   - `claims.Budget != nil`일 때 PIP가 공급한 `env.RemainingBudget`에서 `MaxCalls < 1`이거나, 쓰기 요청 시 `int64(len(req.Data)) > env.RemainingBudget.MaxWriteBytes`이면 즉시 `DecisionDeny`와 `ReasonBudgetExhausted`를 반환한다.
2. **PEP 원자 차감 및 정산 (`internal/authz/pep/gateway.go`)**:
   - 동시 프로세스 경합(TOCTOU)을 막기 위해 실제 원자적 보증은 PEP의 `runPipeline` 내부에서 수행하는 `budgetLedger.Consume(...)`이 담당한다.
   - `file:read`의 경우: 읽기 수행 후 읽힌 바이트(`len(data)`)에 대해 `Consume(jti, 1, int64(len(data)), 0, now)`를 수행하고, 만약 `ReasonBudgetExhausted`가 반환되면 읽은 데이터를 즉시 폐기(`res.Data = nil`)하고 `ExitAuthzDenied(12)`로 거부한다.
   - `file:write`의 경우: 파일 쓰기 전에 `Consume(jti, 1, 0, int64(len(req.Data)), now)`를 먼저 수행하여 예산 초과 시 파일이 단 1바이트도 쓰이지 않게 하고, 만약 이후 감사 실패나 디스크 오류로 쓰기가 실패하면 `finalize`에서 예약분을 반환한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `MaxCalls: 1`인 토큰으로 `pep.Execute` 2회 연속 호출 | 1회차 `ExitSuccess(0)`, 2회차 `ExitAuthzDenied(12)` + `ReasonBudgetExhausted` |
| **TC-040-02** | `MaxWriteBytes: 10`인 토큰으로 11바이트 `file:write` 호출 | `ExitAuthzDenied(12)` + `ReasonBudgetExhausted`, 대상 파일 무변화(0바이트) |
| **TC-040-03** | `MaxReadBytes: 5`인 토큰으로 20바이트 파일 `file:read` 호출 | `ExitAuthzDenied(12)` + `ReasonBudgetExhausted`, 응답 데이터 비노출(`Output == ""`) |
| **TC-040-04** | `TestArchitectureGuardrails` (`TC-060-01`, `TC-060-04`) 실행 | PDP 파일 무의존성 및 PEP 단일 `return` 100% 통과 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp ./internal/authz/pep -run TestBudget` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test -race ./internal/authz/...` 데이터 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] PIP/PDP/PEP 예산 배선 완료 (`TC-060-01`, `TC-060-04` 가드 통과)
- [ ] 호출 횟수·읽기 바이트·쓰기 바이트 초과 차단 및 파일 무변화 검증 완료
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
