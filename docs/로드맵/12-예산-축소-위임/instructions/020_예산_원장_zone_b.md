# [구현지시서 020] Zone B 원자적 예산 원장(`BudgetLedger`) 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [12번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_예산_모델_adr_및_도메인_정의.md](010_예산_모델_adr_및_도메인_정의.md) 완료
> **후속 단계**: [030_교환_서비스_단조_축소_검증.md](030_교환_서비스_단조_축소_검증.md)

---

## 1. 목적 및 배경

토큰 자체는 불변이므로 실제 예산 잔량과 소비 내역은 Zone B의 공유 원장(`budget_ledger.json`)에서 관리해야 한다.
다중 서브프로세스가 동시에 예산을 차감하더라도 총 소비량이 부모 예산을 절대 초과하지 않도록, [`internal/storage/atomic.go`](../../../../internal/storage/atomic.go)의 `AtomicFileStore[T]` 배타 잠금(`syscall.Flock`) 임계 구역 안에서 **잔량 확인 + 차감 + 만료 자식 예약 회수(Reclaim)**를 단일 원자 연산으로 수행하는 `BudgetLedger`를 구현한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authn/budget/ledger.go` [신규]: `AtomicFileStore[BudgetState]` 기반 `Ledger` 구현 (`InitRootBudget`, `ReserveChildBudget`, `Consume`, `SettleOrRefund`, `ReclaimExpired`, `GetRemaining`)
  - `internal/authn/budget/ledger_test.go` [신규]: 동시 고루틴/프로세스 차감 경합 테스트, 크래시 만료 예약 자동 회수 테스트, 손상 파일 Fail-Closed(`ExitInternalError = 16`) 테스트
- **무영향**:
  - 기존 `grants_state.json` 및 `replay_ledger.json`과 파일이 분리되어 기존 저장소에 영향을 주지 않는다.
  - 직접 `syscall.Flock`을 호출하지 않고 `internal/storage.AtomicFileStore`를 사용하므로 AST 가드레일(`TC-081-01`)을 준수한다.

---

## 3. 세부 명세

1. **원장 엔트리 구조 (`BudgetEntry`)**:
   - `TokenJTI string`: 예산이 귀속된 토큰 식별자
   - `ParentJTI string`: 상위 토큰 식별자 (자식 예약 만료 시 미사용분 반환 대상)
   - `Initial domain.Budget`, `Remaining domain.Budget`
   - `ExpiresAt int64`: 토큰 만료 시각 (Unix 초)
   - `Reclaimed bool`: 만료 후 미사용 잔여량이 부모에게 회수 완료되었는지 표시
2. **원자적 만료 회수 (`reclaimExpiredLocked`)**:
   - 모든 원장 갱신 트랜잭션(`Update`) 진입 시 현재 시각(`now.Unix()`) 기준으로 `ExpiresAt <= now && !Reclaimed`인 자식 엔트리를 찾아 남은 `Remaining`을 `ParentJTI` 엔트리의 `Remaining`에 더해주고 `Reclaimed = true`로 마킹한다. 이를 통해 자식이 `kill -9`로 비정상 종료되어도 만료 시각 이후 예산 누수가 `0`이 된다.
3. **원자적 소비 (`Consume(jti string, calls, readBytes, writeBytes int64, now time.Time) error`)**:
   - 단일 `store.Update` 클로저 내부에서 잔량을 검사하고, 부족하면 상태 변경 없이 `domain.NewError(domain.ReasonBudgetExhausted, "budget_ledger", "...", nil)`(`ExitAuthzDenied = 12`)을 반환한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | 잔량 `MaxCalls: 3`인 원장에 10개 고루틴이 동시에 `Consume(calls: 1)` 호출 | 정확히 3건만 `nil` 반환, 7건은 `ReasonBudgetExhausted(12)` 반환, 최종 잔량 `0` |
| **TC-020-02** | 부모(`Calls: 10`)에서 자식(`Calls: 4`, TTL 1분) 예약 후 자식이 1회만 쓰고 크래시 → 가상 시계 +2분 전진 후 부모 잔량 조회 | 만료된 자식의 미사용분(`3`)이 부모에게 자동 회수되어 부모 잔량 `9`(`6 + 3`) 복원 |
| **TC-020-03** | 깨진 JSON이 적힌 원장 파일에서 `Consume` 호출 | Fail-Closed 에러 반환 (`ExitInternalError = 16`) |
| **TC-020-04** | `TC-081-01` AST 가드레일 실행 | `internal/authn/budget`이 직접 `syscall.Flock`을 부르지 않고 `internal/storage`만 사용함 확인 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authn/budget` PASS
2. `go test -race ./internal/authn/budget` 데이터 레이스 0건
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `AtomicFileStore` 기반 `BudgetLedger` 구현 완료
- [ ] 동시 차감 경합 및 만료 크래시 회수 단위 테스트 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
