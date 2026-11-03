# [구현지시서 040] PIP/PDP/PEP 예산 소비·정산 및 단일 합성 루트 자동 경로 배선

> **문서 상태**: `Draft`
> **상위 대시보드**: [12번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [030_교환_서비스_단조_축소_검증.md](030_교환_서비스_단조_축소_검증.md) 완료
> **후속 단계**: [050_g11_e2e_시나리오.md](050_g11_e2e_시나리오.md)

---

## 1. 목적 및 배경

서브에이전트 워커가 도구를 실행할 때 PIP가 토큰별 예산 엔트리를 조회해 공급하고, PDP가 순수 함수로 예산 충분 여부를 판정한 뒤, PEP가 실제 파일 I/O와 맞물려 원자적으로 예산을 차감·정산하도록 배선한다.
특히 부모 프로세스와 자식 서브프로세스 워커(`authz-harness subagent worker`)가 추가 CLI 플래그 변경 없이도 동일한 Zone B 예산 원장(`zone_b/budget_ledger.json`)을 공유하도록 [`internal/app/builder.go`](../../../../internal/app/builder.go)에서 경로를 자동 파생하고, **① PDP의 파일/원장 무의존성(`TC-060-01`)**과 **② PEP `Gateway.Execute`의 단일 출구(`TC-060-04`, `return g.finalize(...)` 단 1개)** 불변식을 100% 보존한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/harness/sandbox.go` 및 `internal/app/builder.go`:
    - `SandboxEnvironment`와 `AppConfig`에 `BudgetPath string` 추가
    - `BuildStack`에서 `cfg.BudgetPath == ""`이고 `cfg.StatePath != ""`이면 `filepath.Join(filepath.Dir(cfg.StatePath), "budget_ledger.json")`으로 자동 파생하여 부모와 자식 워커(`subagent worker -state-file ...`)가 자동으로 동일 원장 파일을 바라보게 함
    - `AppStack`에 `BudgetLedger budget.Ledger` 필드 추가 및 `TokenIssuer`, `PIP`, `PEP`에 자동 주입
  - `internal/authz/pip/service.go`:
    - [015번 보고서](../../../보고서/015-지속적_수정발생_근본원인_진단_및_과잉설계_제거_구조단순화_보고서.md) §2.1에 따라 예산 상태가 `state.GrantsState.Budgets`에 통합되었으므로, 별도 포트 주입 없이 기존 `s.store.Load()` 단 1회 호출만으로 `SubjectSnapshot.BudgetEntries`(`st.Budgets`)를 즉시 채움 (가교 인터페이스 및 다중 파일 로드 완전 제거)
  - `internal/authz/pdp/service.go`:
    - `pdp.Request`에 `TokenJTI string`, `TokenBudget *domain.Budget`, `WriteBytes int64` 추가
    - `Evaluate(req, snapshot)` 순수 함수에서 **활성 Grant 매칭 직후(후속 로드맵 15의 `RequiresApproval` 검사보다 반드시 앞선 Stage 2-6 단계)**에 `req.TokenBudget != nil`일 때 `entry, ok := snapshot.BudgetEntries[req.TokenJTI]`를 조회하여 `!ok || entry.Remaining.MaxCalls < 1`이거나 쓰기 요청 시 `entry.Initial.HasWriteLimit() && req.WriteBytes > entry.Remaining.MaxWriteBytes`이면 즉시 `DecisionDeny` + `ReasonBudgetExhausted(12)` 반환 (`os`나 `storage` import 0건 유지)
  - `internal/authz/pep/gateway.go` ([014번 보고서](../../../보고서/014-모듈레벨_아키텍처원칙_및_내부구현패턴_안티패턴_집중진단_보고서.md) `ARCH-03`, `ARCH-05`):
    - 구체 `internal/authn/budget` 패키지를 import하지 않고 `Config`에 소비자 포트 `BudgetConsumer domain.BudgetConsumer` 선택 필드 추가
    - `runPipeline` 비대화(God Method) 방지를 위해 Stage 3.5 원장 차감 메서드 `stage3PreCommitLedgers(ctx, req, state) (rollback func(), err error)`를 분리하고, Stage 4(감사) 또는 Stage 5(I/O) 실패 시 반환된 `rollback()` 클로저 한 줄로 `BudgetConsumer.Refund`가 결정론적으로 호출되도록 구조화
    - `runPipeline` 내부에서 `verifiedClaims.Claims.Budget != nil`일 때 원자적 `BudgetLedger.Consume` 및 실패 시 `Refund` 수행 (`Execute` 함수 내 `return` 문 1개 유지)
- **무영향**:
  - `Budget == nil`인 토큰은 PIP/PDP/PEP 예산 차감 로직을 그대로 통과하므로 기존 시나리오(`E2E-01`~`E2E-49`)에 영향을 주지 않는다.

---

## 3. 세부 명세

### 3.1 PEP 단일 입출구(`TC-060-04`) 내부의 원자적 차감·정산 순서 (`internal/authz/pep/gateway.go`)
1. `verifiedClaims.Claims.Budget != nil && g.cfg.BudgetLedger != nil`인 경우:
   - **`file:write` 요청**: `Stage4Audit` 직전(또는 `Stage5FileIO` 시작 시점)에 `g.cfg.BudgetLedger.Consume(state.tokenJTI, 1, 0, int64(len(req.Data)), now)`를 먼저 호출한다.
     - 만약 동시 서브프로세스 경합으로 인해 잔여 예산이 소진되었다면 `Consume`이 `ReasonBudgetExhausted`(`ExitAuthzDenied = 12`) 에러를 반환하며, 파일은 단 1바이트도 쓰이지 않는다.
     - 만약 `Consume` 성공 후 `Stage4Audit`(예: `InjectAuditFailure`)이나 디스크 쓰기 오류로 실패하면 `g.cfg.BudgetLedger.Refund(state.tokenJTI, 1, 0, int64(len(req.Data)))`로 차감분을 즉시 복원한다.
   - **`file:read` 요청**: `Stage5FileIO`에서 `Jail.ReadFile`로 읽은 바이트 길이(`int64(len(data))`)를 가지고 `g.cfg.BudgetLedger.Consume(state.tokenJTI, 1, int64(len(data)), 0, now)`를 호출한다.
     - 만약 호출 횟수나 읽기 바이트 한도를 초과하여 `Consume`이 `ReasonBudgetExhausted`를 반환하면, 읽은 `data`를 결과에 담지 않고 폐기한 뒤 즉시 해당 에러를 반환하여 `finalize`가 `ExitAuthzDenied(12)` + `ReasonBudgetExhausted`로 차단하게 한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-040-01** | `MaxCalls: 1`인 토큰으로 `pep.Execute` 2회 연속 호출 | 1회차 `ExitSuccess(0)`, 2회차 `ExitAuthzDenied(12)` + `ReasonBudgetExhausted` (`TOKEN_REPLAY_DETECTED`가 아님 확인) |
| **TC-040-02** | `MaxCalls: 5, MaxWriteBytes: 10`인 토큰으로 11바이트 `file:write` 호출 | `ExitAuthzDenied(12)` + `ReasonBudgetExhausted`, 대상 파일 무변화(0바이트) |
| **TC-040-03** | `MaxCalls: 5, MaxReadBytes: 5`인 토큰으로 20바이트 파일 `file:read` 호출 | `ExitAuthzDenied(12)` + `ReasonBudgetExhausted`, 응답 데이터 비노출(` len(res.Data) == 0`) |
| **TC-040-04** | `TestArchitectureGuardrails` (`TC-060-01`, `TC-060-04`, `TC-081-01`) 실행 | PDP 순수성, PEP 단일 `return`, `AtomicFileStore` 일원화 100% `PASS` |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/pdp ./internal/authz/pep -run TestBudget` PASS
2. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
3. `go test -race ./internal/authz/...` 데이터 레이스 0건
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `BuildStack` 내 `budget_ledger.json` 자동 경로 파생 및 PIP/PDP/PEP 배선 완료
- [ ] `TC-060-01`, `TC-060-04`, `TC-081-01` 가드레일 통과 확인
- [ ] 호출 횟수·읽기 바이트·쓰기 바이트 초과 차단 및 파일 무변화 검증 완료 후 단독 커밋
