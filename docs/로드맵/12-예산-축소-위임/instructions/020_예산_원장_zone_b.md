# [구현지시서 020] Zone B 원자적 예산 원장(`BudgetLedger`) 및 상태 원장 버전(`Version++`) 단조 증가 구현

> **문서 상태**: `Draft`
> **상위 대시보드**: [12번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md)
> **선행 조건**: [010_예산_모델_adr_및_도메인_정의.md](010_예산_모델_adr_및_도메인_정의.md) 완료
> **후속 단계**: [030_교환_서비스_단조_축소_검증.md](030_교환_서비스_단조_축소_검증.md)

---

## 1. 목적 및 배경

토큰 자체는 불변이므로 실제 예산 잔량과 소비 내역은 Zone B의 공유 원장(`budget_ledger.json`)에서 관리해야 한다.
다중 서브프로세스가 동시에 예산을 차감하더라도 총 소비량이 부모 예산을 절대 초과하지 않도록, [`internal/storage/atomic.go`](../../../../internal/storage/atomic.go)의 `AtomicFileStore[T]` 배타 잠금(`syscall.Flock`) 임계 구역 안에서 **만료 자식 예약 회수(Lazy Reclaim) + 잔량 확인 + 차감/예약**을 단일 원자 연산으로 수행하는 `BudgetLedger`를 구현한다.
아울러 [011번 보고서](../../../보고서/011-권한관리_본질_코어파이프라인_안티패턴_및_분산적응형_기본구조_전문가진단_보고서.md) 제안 4에 따라, [`internal/authz/state/store.go`](../../../../internal/authz/state/store.go)의 `GrantsState`와 신규 `BudgetState`가 `Update` 시마다 `Version`을 `1, 2, 3...`으로 **단조 증가(`Version++`)**시키도록 활성화하여 감사 로그의 정책 버전 추적과 향후 분산 환경(CAS/캐시 무효화) 적응력을 함께 확보한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authz/state/budget.go` [신규] 및 `internal/authz/state/store.go`: 별도 패키지나 별도 파일(`budget_ledger.json`)을 만들지 않고 기존 `GrantsState`(`grants_state.json`)에 `Budgets map[string]domain.BudgetEntry`를 통합하여 단일 `state.Store`에서 원자적 관리 ([015번 보고서](../../../보고서/015-지속적_수정발생_근본원인_진단_및_과잉설계_제거_구조단순화_보고서.md) §2.1) (`InitBudget`, `ReserveChildBudget`, `Consume`, `Refund`, `GetEntry`, `GetRemaining`), `Update`마다 `BudgetState.Version++` 단조 증가
  - `internal/authz/state/store.go`: `Update` 시 `GrantsState.Version++`가 단조 증가하도록 `normalizeState` 보강 ([011번 보고서](../../../보고서/011-권한관리_본질_코어파이프라인_안티패턴_및_분산적응형_기본구조_전문가진단_보고서.md) 제안 4)
  - `internal/authz/state/budget_test.go` [신규]: 동시 고루틴/프로세스 차감 경합 테스트, 크래시 만료 예약 자동 회수 테스트, `Initial` 바이트 한도 활성/비활성 구분 테스트, `Version++` 단조 증가 검증, 손상 파일 Fail-Closed(`ExitInternalError = 16`) 테스트
- **무영향**:
  - 기존 `grants_state.json` 및 `replay_ledger.json`과 하위 호환되며, 직접 `syscall.Flock`을 호출하지 않고 `internal/storage.AtomicFileStore`를 사용하므로 AST 가드레일(`TC-081-01`)을 완벽히 준수한다.

---

## 3. 세부 명세

### 3.1 원장 엔트리 구조 (`domain.BudgetEntry` 재사용 및 `domain.BudgetSnapshotReader` 구현) 및 상태 버전 단조 증가
- `010`에서 `internal/domain/budget.go`에 정의한 `domain.BudgetEntry`를 그대로 사용하여 중복 구조체 정의를 방지하고, `FileLedger`가 `domain.BudgetSnapshotReader`(`ListEntries(now time.Time) (map[string]domain.BudgetEntry, error)`)를 구현하여 `internal/authz/pip`(Layer 2B)가 `internal/authn/budget`(Layer 2A)을 직접 import하지 않고도 예산 스냅샷을 조회할 수 있게 한다.
```go
type BudgetEntry struct {
    TokenJTI  string        `json:"token_jti"`
    ParentJTI string        `json:"parent_jti,omitempty"`
    Initial   domain.Budget `json:"initial"`
    Remaining domain.Budget `json:"remaining"`
    ExpiresAt int64         `json:"expires_at"`
    Reclaimed bool          `json:"reclaimed,omitempty"`
}
```
- `Initial`을 함께 보존하여 해당 토큰이 읽기 바이트 한도(`Initial.HasReadLimit()`)나 쓰기 바이트 한도(`Initial.HasWriteLimit()`)를 설정했는지 판별한다.
- `GrantsState`와 `BudgetState` 모두 `Update` 트랜잭션이 성공할 때마다 `state.Version++`로 단조 증가시킨다.

### 3.2 원자적 만료 회수 (`reclaimExpiredLocked(st *BudgetState, now time.Time)`)
- 모든 쓰기 트랜잭션(`ReserveChildBudget`, `Consume`, `GetRemaining`) 내부에서 `nowUnix := now.UTC().Unix()` 기준으로 `e.ParentJTI != "" && !e.Reclaimed && e.ExpiresAt <= nowUnix`인 자식 엔트리를 탐색한다.
- 위임 체인 깊은 곳(Depth 2 → Depth 1 → Depth 0)부터 부모에게 미사용분이 귀속되도록 처리하며, `parent.Remaining.MaxCalls += child.Remaining.MaxCalls` (바이트 한도 활성 시 바이트도 합산, 단 `parent.Initial` 상한 이하로 클램핑), `child.Remaining = domain.Budget{}`, `child.Reclaimed = true`로 갱신한다.

### 3.3 예약(`ReserveChildBudget`) 및 소비(`Consume`) 규칙
1. `ReserveChildBudget(parentJTI, childJTI string, reqBudget domain.Budget, childExp int64, now time.Time) error`:
   - `reclaimExpiredLocked` 수행 후 `parent` 엔트리를 조회한다.
   - `reqBudget.MaxCalls > parent.Remaining.MaxCalls`이면 `domain.NewError(domain.ReasonDelegationBudgetExceeded, "budget_ledger", "...", nil)`(`ExitAuthzDenied = 12`)을 반환한다.
   - `parent.Initial.HasReadLimit()`인데 `!reqBudget.HasReadLimit() || reqBudget.MaxReadBytes > parent.Remaining.MaxReadBytes`이면 `ReasonDelegationBudgetExceeded`를 반환한다 (`Write`도 동일).
   - 통과 시 `parent.Remaining`에서 `reqBudget`만큼 차감하고 `childJTI` 엔트리를 등록한다.
2. `Consume(jti string, calls, readBytes, writeBytes int64, now time.Time) error`:
   - `entry.Remaining.MaxCalls < calls`이면 `ReasonBudgetExhausted`(`12`) 반환.
   - `entry.Initial.HasReadLimit() && entry.Remaining.MaxReadBytes < readBytes`이면 `ReasonBudgetExhausted`(`12`) 반환.
   - `entry.Initial.HasWriteLimit() && entry.Remaining.MaxWriteBytes < writeBytes`이면 `ReasonBudgetExhausted`(`12`) 반환.
   - 통과 시 `entry.Remaining`에서 해당 수치를 차감한다.

---

> **Coffman 교착 상태 방지를 위한 중첩 파일 락 금지 불변식 ([013번 보고서](../../../보고서/013-5대_표준공학검증기법_기반_잔여로드맵_전수정밀진단_및_교정_보고서.md) `DEF-05`)**: `AtomicFileStore.Update(fn)`(또는 `WithFileLock`) 콜백 `fn` 내부에서는 인메모리 상태 구조체만 변이하고 즉시 반환해야 하며, 락을 쥔 채로 `auditWriter.Log(...)`나 다른 `AtomicFileStore`를 중첩 호출하지 않는다(감사 기록 등은 반드시 `Update` 반환 직후 수행).

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | 잔량 `MaxCalls: 3`인 원장에 10개 고루틴이 동시에 `Consume(calls: 1)` 호출 | 정확히 3건만 `nil` 반환, 7건은 `ReasonBudgetExhausted(12)` 반환, 최종 잔량 `0`, `Version` 단조 증가 확인 |
| **TC-020-02** | 부모(`Calls: 10`)에서 자식(`Calls: 4`, TTL 1분) 예약 후 자식이 1회만 쓰고 크래시 → 가상 시계 +2분 전진 후 부모에서 새 자식(`Calls: 8`) 예약 | 만료된 자식의 미사용분(`3`)이 자동 회수되어 부모 잔량 `9`(`6 + 3`)가 되고 새 자식(`8`) 예약 성공 |
| **TC-020-03** | 깨진 JSON이 적힌 원장 파일에서 `Consume` 호출 | Fail-Closed 에러 반환 (`ExitInternalError = 16`) |
| **TC-020-04** | `TC-081-01` AST 가드레일 실행 | `internal/authn/budget`이 직접 `syscall.Flock`을 부르지 않고 `internal/storage`만 사용함 확인 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authz/state` PASS
2. `go test -race ./internal/authz/state` 데이터 레이스 0건
3. `go test -v ./internal/harness -run TestArchitectureGuardrails/TC-081-01` PASS
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [ ] `AtomicFileStore` 기반 `BudgetLedger` 및 `GrantsState`/`BudgetState` `Version++` 단조 증가 구현 완료
- [ ] 동시 차감 경합 및 만료 크래시 회수 단위 테스트 통과
- [ ] 대시보드 상태 갱신 및 변경 파일 단독 커밋
