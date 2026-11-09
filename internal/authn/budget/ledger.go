// Package budget 은 Zone B 예산 영구 원장(budget_ledger.json)을 제공한다.
//
// [토큰 예산 아키텍처와 원자적 자원 통제]
// 1. 토큰 내 상한(Budget)과 원장(Ledger)의 분리:
//    - Bearer JWT 토큰은 오직 허용된 최대 소비 상한(Initial Budget)만을 불변 클레임으로 담는다.
//    - 실제 사용 가능한 잔여 예산(Remaining Budget)은 Zone B 디스크 원장에서 배타 락(flock) 임계 구역 안에서 원자적으로 차감/정산된다.
// 2. 부모-자식 예산 분할 예약 (Reservation):
//    - 축소 위임 시 자식 토큰의 예산은 부모의 Remaining 예산에서 즉시 떼어내어 자식 엔트리로 이전된다.
//    - 이로써 부모와 자식이 동일한 예산을 동시에 이중 지출(Double Spending)하는 보안 취약점을 차단한다.
// 3. 만료된 자식 미사용분의 상향 환원 (Bottom-Up Expiry Reclamation):
//    - 자식 토큰이 만료(ExpiresAt <= now)되면, 미처 소비하지 못한 잔여 예산은 가장 깊은 자식부터(depth 내림차순)
//      부모 토큰의 Remaining 으로 안전하게 자동 회수(Reclaim)되어 자원 낭비를 방지한다.
// 4. LIFO 환불 상한 방어 (addCapped):
//    - 파이프라인 장애 보상(Refund) 시 차감분을 돌려주되, 결코 최초 발급 상한(Initial)을 초과하지 않도록 캡(Cap)을 씌운다.
package budget

import (
	"errors"
	"fmt"
	"sort"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

// Entry 는 토큰 하나의 예산 장부 레코드 엔트리다.
type Entry struct {
	// TokenJTI 는 해당 토큰의 고유 식별자다.
	TokenJTI string `json:"token_jti"`

	// ParentJTI 는 이 예산의 원천이 된 부모 토큰의 JTI 다 (루트 토큰은 빈 문자열 "").
	ParentJTI string `json:"parent_jti,omitempty"`

	// Initial 은 발급 당시 확정된 불변의 최대 허용 상한이다 (바이트 한도 활성 여부 판별의 기준).
	Initial domain.Budget `json:"initial"`

	// Remaining 은 현재 사용 가능한 잔여 예산이다 (호출 횟수, 읽기 바이트, 쓰기 바이트).
	Remaining domain.Budget `json:"remaining"`

	// ExpiresAt 은 토큰의 Unix 만료 시각(초)이다. 만료 회수(Reclaim)의 기준이 된다.
	ExpiresAt int64 `json:"expires_at"`

	// Reclaimed 는 토큰 만료 후 미사용 잔량이 부모에게 환원 완료되었는지 여부를 나타내는 플래그다.
	Reclaimed bool `json:"reclaimed,omitempty"`
}

// LedgerState 는 budget_ledger.json 파일에 영속화되는 루트 JSON 구조체다.
type LedgerState struct {
	Entries map[string]Entry `json:"entries"`
}

// Ledger 는 예산 장부의 수명주기 및 차감/환불을 제어하는 DIP 인터페이스다.
type Ledger interface {
	// Init 는 루트 토큰 예산 엔트리를 최초 등록한다.
	Init(jti string, b domain.Budget, exp int64) error

	// Reserve 는 부모 토큰의 잔여 예산에서 req 만큼 떼어 자식 토큰 엔트리로 분할 예약한다.
	Reserve(parentJTI, childJTI string, req domain.Budget, childExp int64) error

	// Consume 은 도구 실행 전/후에 호출 횟수 또는 I/O 바이트를 원자적으로 차감한다.
	Consume(jti string, calls, readBytes, writeBytes int64) error

	// Refund 는 파이프라인 후속 장애 시 선차감했던 예산을 안전하게 환불/복구한다 (Initial 상한 보장).
	Refund(jti string, calls, readBytes, writeBytes int64) error

	// Get 은 특정 토큰의 예산 엔트리를 읽기 전용으로 조회한다.
	Get(jti string) (Entry, bool, error)
}

// FileLedger 는 storage.AtomicFileStore 기반으로 배타적 파일 락을 보장하는 Ledger 구현체다.
type FileLedger struct {
	store *storage.AtomicFileStore[LedgerState]
	clock domain.Clock
}

var _ Ledger = (*FileLedger)(nil)

// Ledger 는 관문이 쓰는 domain.BudgetLedger 포트를 만족해야 한다 (시그니처 일치 고정).
var _ domain.BudgetLedger = Ledger(nil)

// NewFileLedger 는 지정된 경로의 budget_ledger.json 을 다루는 FileLedger 인스턴스를 생성한다.
func NewFileLedger(path string, clock domain.Clock) (*FileLedger, error) {
	if clock == nil {
		clock = domain.RealClock{}
	}
	store := storage.NewAtomicFileStore(
		path,
		storage.WithPerm[LedgerState](0644), // Zone B 공용 파일 퍼미션
		storage.WithDefault(func() *LedgerState {
			return &LedgerState{Entries: map[string]Entry{}}
		}),
	)
	l := &FileLedger{store: store, clock: clock}
	if _, err := store.Read(); err != nil {
		return nil, domain.NewError(domain.ReasonInternalError, "failed to initialize budget ledger", err)
	}
	return l, nil
}

// update 는 만료 회수(reclaimExpiredLocked)를 먼저 수행한 뒤 fn 을 배타 락 임계 구역 안에서 안전하게 실행한다.
func (l *FileLedger) update(fn func(st *LedgerState) error) error {
	err := l.store.Update(func(st *LedgerState) error {
		if st.Entries == nil {
			st.Entries = map[string]Entry{}
		}
		reclaimExpiredLocked(st, l.clock.Now().Unix())
		return fn(st)
	})
	return classify(err)
}

// classify 는 저장소 입출력 에러를 domain.Error 로 안전하게 정규화한다.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var de *domain.Error
	if errors.As(err, &de) {
		return err
	}
	return domain.NewError(domain.ReasonInternalError, "budget ledger I/O failure", err)
}

// Init 는 루트 예산 엔트리를 등록한다. 동일한 jti 가 이미 존재하면 거부한다.
func (l *FileLedger) Init(jti string, b domain.Budget, exp int64) error {
	if err := b.Validate(); err != nil {
		return err
	}
	return l.update(func(st *LedgerState) error {
		if _, ok := st.Entries[jti]; ok {
			return domain.NewError(domain.ReasonDelegationBudgetExceeded, "budget entry already exists", nil)
		}
		st.Entries[jti] = Entry{TokenJTI: jti, Initial: b, Remaining: b, ExpiresAt: exp}
		return nil
	})
}

// Reserve 는 부모 토큰 잔여 예산에서 req 만큼 떼어 자식 엔트리로 분할 예약한다 (이중 지출 방어).
func (l *FileLedger) Reserve(parentJTI, childJTI string, req domain.Budget, childExp int64) error {
	if err := req.Validate(); err != nil {
		return err
	}
	denied := func(msg string) error {
		return domain.NewError(domain.ReasonDelegationBudgetExceeded, msg, nil)
	}
	return l.update(func(st *LedgerState) error {
		parent, ok := st.Entries[parentJTI]
		if !ok || parent.Reclaimed {
			return denied("parent budget entry not found")
		}
		if _, dup := st.Entries[childJTI]; dup {
			return denied("child budget entry already exists")
		}
		if req.MaxCalls > parent.Remaining.MaxCalls {
			return denied("child calls exceed parent remaining")
		}
		if parent.Initial.HasReadLimit() &&
			(!req.HasReadLimit() || req.MaxReadBytes > parent.Remaining.MaxReadBytes) {
			return denied("child read bytes exceed parent remaining")
		}
		if parent.Initial.HasWriteLimit() &&
			(!req.HasWriteLimit() || req.MaxWriteBytes > parent.Remaining.MaxWriteBytes) {
			return denied("child write bytes exceed parent remaining")
		}
		parent.Remaining.MaxCalls -= req.MaxCalls
		if parent.Initial.HasReadLimit() {
			parent.Remaining.MaxReadBytes -= req.MaxReadBytes
		}
		if parent.Initial.HasWriteLimit() {
			parent.Remaining.MaxWriteBytes -= req.MaxWriteBytes
		}
		st.Entries[parentJTI] = parent
		st.Entries[childJTI] = Entry{
			TokenJTI: childJTI, ParentJTI: parentJTI,
			Initial: req, Remaining: req, ExpiresAt: childExp,
		}
		return nil
	})
}

func checkAmounts(calls, readBytes, writeBytes int64) error {
	if calls < 0 || readBytes < 0 || writeBytes < 0 {
		return domain.NewError(domain.ReasonInvalidArguments, "negative budget amount", nil)
	}
	return nil
}

// Consume 은 엔트리에서 호출 수 및 I/O 바이트를 원자적으로 차감한다. 잔여량이 부족하면 어떤 값도 변경하지 않고 거부한다.
func (l *FileLedger) Consume(jti string, calls, readBytes, writeBytes int64) error {
	if err := checkAmounts(calls, readBytes, writeBytes); err != nil {
		return err
	}
	exhausted := func(msg string) error {
		return domain.NewError(domain.ReasonBudgetExhausted, msg, nil)
	}
	return l.update(func(st *LedgerState) error {
		e, ok := st.Entries[jti]
		if !ok {
			return exhausted("budget entry not found")
		}
		if e.Reclaimed {
			return exhausted("budget entry reclaimed after expiry")
		}
		if e.Remaining.MaxCalls < calls {
			return exhausted("call budget exhausted")
		}
		if e.Initial.HasReadLimit() && e.Remaining.MaxReadBytes < readBytes {
			return exhausted("read byte budget exhausted")
		}
		if e.Initial.HasWriteLimit() && e.Remaining.MaxWriteBytes < writeBytes {
			return exhausted("write byte budget exhausted")
		}
		e.Remaining.MaxCalls -= calls
		if e.Initial.HasReadLimit() {
			e.Remaining.MaxReadBytes -= readBytes
		}
		if e.Initial.HasWriteLimit() {
			e.Remaining.MaxWriteBytes -= writeBytes
		}
		st.Entries[jti] = e
		return nil
	})
}

// Refund 는 파이프라인 후속 단계 장애 시 차감분을 안전하게 복구한다 (Initial 상한 보장).
func (l *FileLedger) Refund(jti string, calls, readBytes, writeBytes int64) error {
	if err := checkAmounts(calls, readBytes, writeBytes); err != nil {
		return err
	}
	return l.update(func(st *LedgerState) error {
		e, ok := st.Entries[jti]
		if !ok {
			return domain.NewError(domain.ReasonInternalError, "budget entry not found for refund", nil)
		}
		if e.Reclaimed {
			return nil
		}
		e.Remaining = addCapped(e.Remaining, domain.Budget{MaxCalls: calls, MaxReadBytes: readBytes, MaxWriteBytes: writeBytes}, e.Initial)
		st.Entries[jti] = e
		return nil
	})
}

// Get 은 공유 잠금으로 특정 엔트리를 읽어들인다 (만료 회수를 트리거하지 않음).
func (l *FileLedger) Get(jti string) (Entry, bool, error) {
	st, err := l.store.Read()
	if err != nil {
		return Entry{}, false, classify(fmt.Errorf("read budget ledger: %w", err))
	}
	e, ok := st.Entries[jti]
	return e, ok, nil
}

// reclaimExpiredLocked 는 만료된 자식 토큰의 미사용 잔여분을 가장 깊은 자식부터(depth 내림차순) 부모에게 안전하게 환원한다.
func reclaimExpiredLocked(st *LedgerState, nowUnix int64) {
	type item struct {
		jti   string
		depth int
	}
	var due []item
	for jti, e := range st.Entries {
		if e.ParentJTI != "" && !e.Reclaimed && e.ExpiresAt <= nowUnix {
			due = append(due, item{jti, depthOf(st, jti)})
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if due[i].depth != due[j].depth {
			return due[i].depth > due[j].depth
		}
		return due[i].jti < due[j].jti
	})
	for _, it := range due {
		child := st.Entries[it.jti]
		if parent, ok := st.Entries[child.ParentJTI]; ok {
			parent.Remaining = addCapped(parent.Remaining, child.Remaining, parent.Initial)
			st.Entries[child.ParentJTI] = parent
			child.Remaining = domain.Budget{}
		}
		child.Reclaimed = true
		st.Entries[it.jti] = child
	}
}

// depthOf 는 위임 트리 내에서 특정 JTI 의 위임 깊이를 계산한다 (순환 루프 방어 포함).
func depthOf(st *LedgerState, jti string) int {
	d := 0
	for seen := 0; seen <= len(st.Entries); seen++ {
		p := st.Entries[jti].ParentJTI
		if p == "" {
			return d
		}
		d++
		jti = p
	}
	return d // 순환 방어
}

// addCapped 는 rem 에 delta 를 더하되 결코 initial 상한을 넘지 않도록 상한(Cap)을 강제한다.
func addCapped(rem, delta, initial domain.Budget) domain.Budget {
	rem.MaxCalls = minInt64(rem.MaxCalls+delta.MaxCalls, initial.MaxCalls)
	if initial.HasReadLimit() {
		rem.MaxReadBytes = minInt64(rem.MaxReadBytes+delta.MaxReadBytes, initial.MaxReadBytes)
	}
	if initial.HasWriteLimit() {
		rem.MaxWriteBytes = minInt64(rem.MaxWriteBytes+delta.MaxWriteBytes, initial.MaxWriteBytes)
	}
	return rem
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
