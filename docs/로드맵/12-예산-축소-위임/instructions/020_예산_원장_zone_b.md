# [구현지시서 020] Zone B 예산 원장(`internal/authn/budget`) 구현

> **문서 상태**: `Done` (2026-11-04)
> **상위 대시보드**: [12번 README.md](../README.md) | [ROADMAP.md](../ROADMAP.md) | 교정 근거: [021번 보고서](../../../보고서/021-12번로드맵_구조결함_및_진행가능성_검증보고서.md) B-1·B-6·B-7
> **선행 조건**: [010_예산_모델_adr_및_도메인_정의.md](010_예산_모델_adr_및_도메인_정의.md) 완료
> **후속 단계**: [030_교환_서비스_단조_축소_검증.md](030_교환_서비스_단조_축소_검증.md)

---

## 1. 목적 및 배경

토큰은 불변이므로 실제 잔량은 Zone B의 원장 파일 `budget_ledger.json`에 둔다. 여러 서브프로세스가 동시에 차감해도 합계가 넘지 않도록, [`internal/storage/atomic.go`](../../../../internal/storage/atomic.go)의 `AtomicFileStore[T]` 배타 잠금 임계 구역 하나 안에서 **만료 회수 → 잔량 확인 → 차감/예약**을 한 번에 수행한다.

구조는 기존 Replay 원장([`authn/token/replay.go`](../../../../internal/authn/token/replay.go) `FileReplayLedger`)을 그대로 따른다: Zone B 파일 하나, `AtomicFileStore` 사용, 생성자에 시계 주입. 정책 파일 `grants_state.json`과는 **합치지 않는다**(소비 카운터가 쓰일 때마다 정책 파일 전체를 다시 쓰지 않기 위해, 그리고 PIP·PDP를 바꾸지 않기 위해).

정책 버전 `Version++` 활성화(011 제안 4)는 예산과 무관하므로 본 단계와 12번 로드맵 범위에서 제외한다.

---

## 2. 파급 범위와 무영향 근거

- **변경**:
  - `internal/authn/budget/ledger.go` [신규]: `Entry`, `LedgerState`, `Ledger` 인터페이스, `FileLedger` 구현
  - `internal/authn/budget/ledger_test.go` [신규]: 동시 고루틴·다중 프로세스 경합, 만료 회수, 바이트 한도 활성/비활성, 손상 파일 Fail-Closed
- **무영향**: 새 패키지만 추가한다. 아직 누구도 호출하지 않는다(030부터 배선). `internal/authn` 아래이므로 `TC-081-01`(직접 `syscall.Flock` 금지)이 자동 적용된다.

---

## 3. 세부 명세

### 3.1 자료 구조

```go
// Entry 는 토큰 하나의 예산 장부 줄이다.
type Entry struct {
    TokenJTI  string        `json:"token_jti"`
    ParentJTI string        `json:"parent_jti,omitempty"` // 루트는 빈 값
    Initial   domain.Budget `json:"initial"`              // 바이트 한도 활성 여부 판별용 (불변)
    Remaining domain.Budget `json:"remaining"`
    ExpiresAt int64         `json:"expires_at"`           // 토큰 exp (Unix 초)
    Reclaimed bool          `json:"reclaimed,omitempty"`  // 만료 회수 완료 표시
}

type LedgerState struct {
    Entries map[string]Entry `json:"entries"`
}

type Ledger interface {
    Init(jti string, b domain.Budget, exp int64) error
    Reserve(parentJTI, childJTI string, req domain.Budget, childExp int64) error
    Consume(jti string, calls, readBytes, writeBytes int64) error
    Refund(jti string, calls, readBytes, writeBytes int64) error
    Get(jti string) (Entry, bool, error)
}

func NewFileLedger(path string, clock domain.Clock) (*FileLedger, error)
```

- 시각은 인자가 아니라 생성자에 주입한 `clock.Now()`로 얻는다(Replay 원장과 같은 방식). 테스트는 시계를 바꾼 두 번째 `FileLedger`를 같은 경로로 만들어 시간 경과를 흉내낸다.
- 파일 권한·디렉터리 생성은 `state.NewFileStore`·`NewFileReplayLedger`와 같게 한다.

### 3.2 만료 회수 (`reclaimExpiredLocked(st *LedgerState, nowUnix int64)`)
- `Reserve`·`Consume`·`Refund` 트랜잭션의 맨 앞에서 호출한다. `Get`은 읽기 전용(`Read`)이며 회수하지 않는다.
- 대상: `e.ParentJTI != "" && !e.Reclaimed && e.ExpiresAt <= nowUnix`.
- **깊은 엔트리부터** 처리한다(체인 깊이 = 부모를 따라 올라간 횟수, 큰 것부터). 그래야 손자 → 자식 → 루트로 미사용분이 한 트랜잭션 안에서 끝까지 올라간다.
- 처리: 부모 엔트리가 있으면 `parent.Remaining.MaxCalls += child.Remaining.MaxCalls`, 활성 바이트 한도도 합산하되 각 값은 `parent.Initial` 이하로 자른다. 그다음 `child.Remaining = domain.Budget{}`, `child.Reclaimed = true`. 부모 엔트리가 없으면(손상 이외 정상 경로에서는 생기지 않음) 회수하지 않고 `Reclaimed = true`만 표시한다.

### 3.3 연산 규칙

| 연산 | 규칙 | 실패 |
|---|---|---|
| `Init` | `b.Validate()` 통과, 같은 jti가 이미 있으면 거부(재등록으로 예산 부활 방지). `Initial = Remaining = b`. | 무효 예산 `ReasonInvalidArguments`(14), 중복 `ReasonDelegationBudgetExceeded`(12) |
| `Reserve` | 회수 → 부모 조회 → `req.Validate()` → `req.Within(parent.Remaining)`처럼 비교(호출 수, 그리고 `parent.Initial`의 활성 바이트 한도마다 `req`도 한도가 있어야 하고 `parent.Remaining` 이하) → `parent.Remaining`에서 차감 → 자식 엔트리 등록(`Initial = Remaining = req`, `ParentJTI = parentJTI`). 자식 jti가 이미 있으면 거부. | 부모 없음·부족·자식 중복 `ReasonDelegationBudgetExceeded`(12) |
| `Consume` | 회수 → 엔트리 조회 → `Reclaimed`면 거부 → `Remaining.MaxCalls < calls`, 또는 `Initial.HasReadLimit() && Remaining.MaxReadBytes < readBytes`, 또는 쓰기 동일이면 거부 → 차감. 비활성 바이트 한도는 검사·차감하지 않는다. | 엔트리 없음·회수됨·부족 `ReasonBudgetExhausted`(12) |
| `Refund` | 회수 → 엔트리 조회 → `Remaining`에 더하되 `Initial` 이하로 자른다. 회수된 엔트리는 아무것도 하지 않는다(이미 부모로 돌아갔으므로 이중 계상 방지). | 엔트리 없음 `ReasonInternalError`(16) |
| `Get` | 공유 잠금 읽기. | — |

- 원장 파일 손상(JSON 파싱 실패)은 모든 연산에서 `ReasonInternalError`(`16`)로 끝난다. 빈 원장으로 다시 시작하지 않는다.

> **중첩 잠금 금지 불변식** ([013번 보고서](../../../보고서/013-5대_표준공학검증기법_기반_잔여로드맵_전수정밀진단_및_교정_보고서.md) `DEF-05`): `AtomicFileStore.Update(fn)`의 `fn` 안에서는 메모리 상태만 바꾸고 즉시 반환한다. 감사 기록이나 다른 `AtomicFileStore` 호출은 `Update`가 끝난 뒤에 한다.

---

## 4. 인수 테스트 시나리오

| ID | 입력 | 기대 결과 |
|:---:|---|---|
| **TC-020-01** | 루트 `Init(MaxCalls: 3)` 후 10개 고루틴이 동시에 `Consume(1,0,0)` | 정확히 3건 `nil`, 7건 `ReasonBudgetExhausted(12)`, 최종 `Remaining.MaxCalls == 0` |
| **TC-020-02** | 같은 원장 파일을 연 **별도 프로세스** 6개(테스트 바이너리 재실행 `TestHelperProcess` 방식)가 각 1회 `Consume`, 루트 `MaxCalls: 3` | 성공 프로세스 정확히 3개, 최종 잔량 `0` |
| **TC-020-03** | 부모 `Calls: 10` → 자식(`Calls: 4`, exp = 기준 + 60초) 예약 → 자식 `Consume` 1회 → 기준 + 120초 시계의 원장으로 새 자식(`Calls: 8`) 예약 | 회수로 부모 잔량 `6 + 3 = 9`, 새 자식 예약 성공(부모 잔량 `1`), 첫 자식 `Reclaimed == true` |
| **TC-020-04** | `Initial{MaxCalls: 5}`(바이트 한도 없음)에 `Consume(1, 1000, 1000)` / `Initial{MaxCalls: 5, MaxWriteBytes: 20}`에 `Consume(1,0,10)` 2회 후 `Consume(1,0,1)` | 앞은 성공 / 뒤는 3회차 `ReasonBudgetExhausted` |
| **TC-020-05** | 쓰기 한도가 있는 부모에서 쓰기 한도가 없는 자식 예약 | `ReasonDelegationBudgetExceeded(12)` |
| **TC-020-06** | 원장에 없는 부모 jti로 `Reserve` / 없는 jti로 `Consume` | 각각 `ReasonDelegationBudgetExceeded(12)` / `ReasonBudgetExhausted(12)` |
| **TC-020-07** | 깨진 JSON이 적힌 원장 파일에서 `Consume` | `ReasonInternalError(16)`, 파일 내용 그대로 |
| **TC-020-08** | `Consume(1,0,10)` 후 `Refund(1,0,10)` / 회수된 엔트리에 `Refund` | 잔량 원복 / 잔량 변화 없음 |

---

## 5. 4층위 검증 기준

1. `go test -v ./internal/authn/budget` PASS
2. `go test -race ./internal/authn/budget` 레이스 0건
3. `go test -v ./internal/harness -run TestArchitectureGuardrails` PASS (`TC-081-01` 포함)
4. `go test ./...` 전체 회귀 0건

---

## 6. 완료 판정 체크리스트

- [x] `internal/authn/budget` `FileLedger`(`Init`/`Reserve`/`Consume`/`Refund`/`Get`, 만료 회수) 구현
- [x] 고루틴·다중 프로세스 경합, 만료 회수, 손상 Fail-Closed 테스트 통과
- [x] 대시보드 상태 갱신 및 변경 파일 단독 커밋
