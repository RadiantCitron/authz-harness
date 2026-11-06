// Package budget 은 Zone B 예산 원장(budget_ledger.json)을 제공한다.
// 토큰은 상한만 담고, 실제 잔량은 이 원장에서 배타 잠금 임계 구역 안에서 원자적으로 차감한다.
package budget

import (
	"errors"
	"fmt"
	"sort"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

// Entry 는 토큰 하나의 예산 장부 줄이다.
type Entry struct {
	TokenJTI  string        `json:"token_jti"`
	ParentJTI string        `json:"parent_jti,omitempty"` // 루트는 빈 값
	Initial   domain.Budget `json:"initial"`              // 바이트 한도 활성 여부 판별용 (불변)
	Remaining domain.Budget `json:"remaining"`
	ExpiresAt int64         `json:"expires_at"`          // 토큰 exp (Unix 초)
	Reclaimed bool          `json:"reclaimed,omitempty"` // 만료 회수 완료 표시
}

// LedgerState 는 budget_ledger.json 에 영속화되는 루트 데이터다.
type LedgerState struct {
	Entries map[string]Entry `json:"entries"`
}

// Ledger 는 예산 원장 인터페이스다.
type Ledger interface {
	Init(jti string, b domain.Budget, exp int64) error
	Reserve(parentJTI, childJTI string, req domain.Budget, childExp int64) error
	Consume(jti string, calls, readBytes, writeBytes int64) error
	Refund(jti string, calls, readBytes, writeBytes int64) error
	Get(jti string) (Entry, bool, error)
}

// FileLedger 는 storage.AtomicFileStore 기반 Ledger 구현체다.
type FileLedger struct {
	store *storage.AtomicFileStore[LedgerState]
	clock domain.Clock
}

var _ Ledger = (*FileLedger)(nil)

// NewFileLedger 는 path 의 원장 파일을 다루는 FileLedger 를 생성한다.
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

// update 는 만료 회수 후 fn 을 임계 구역에서 실행한다. 저장소 I/O·파싱 오류는 16 으로 분류한다.
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

// Init 는 루트 예산 엔트리를 등록한다. 같은 jti 의 재등록은 거부한다.
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

// Reserve 는 부모 잔여에서 req 를 떼어 자식 엔트리로 옮긴다.
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

// Consume 는 엔트리에서 호출 수·바이트를 차감한다. 부족하면 어떤 값도 바꾸지 않는다.
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

// Refund 는 차감분을 되돌린다(Initial 상한). 회수된 엔트리는 이중 계상 방지를 위해 무시한다.
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
		e.Remaining.MaxCalls = minInt64(e.Remaining.MaxCalls+calls, e.Initial.MaxCalls)
		if e.Initial.HasReadLimit() {
			e.Remaining.MaxReadBytes = minInt64(e.Remaining.MaxReadBytes+readBytes, e.Initial.MaxReadBytes)
		}
		if e.Initial.HasWriteLimit() {
			e.Remaining.MaxWriteBytes = minInt64(e.Remaining.MaxWriteBytes+writeBytes, e.Initial.MaxWriteBytes)
		}
		st.Entries[jti] = e
		return nil
	})
}

// Get 는 공유 잠금으로 엔트리를 읽는다(회수하지 않음).
func (l *FileLedger) Get(jti string) (Entry, bool, error) {
	st, err := l.store.Read()
	if err != nil {
		return Entry{}, false, classify(fmt.Errorf("read budget ledger: %w", err))
	}
	e, ok := st.Entries[jti]
	return e, ok, nil
}

// reclaimExpiredLocked 는 만료된 자식의 미사용분을 깊은 엔트리부터 부모로 돌려준다.
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
			parent.Remaining.MaxCalls = minInt64(parent.Remaining.MaxCalls+child.Remaining.MaxCalls, parent.Initial.MaxCalls)
			if parent.Initial.HasReadLimit() {
				parent.Remaining.MaxReadBytes = minInt64(parent.Remaining.MaxReadBytes+child.Remaining.MaxReadBytes, parent.Initial.MaxReadBytes)
			}
			if parent.Initial.HasWriteLimit() {
				parent.Remaining.MaxWriteBytes = minInt64(parent.Remaining.MaxWriteBytes+child.Remaining.MaxWriteBytes, parent.Initial.MaxWriteBytes)
			}
			st.Entries[child.ParentJTI] = parent
			child.Remaining = domain.Budget{}
		}
		child.Reclaimed = true
		st.Entries[it.jti] = child
	}
}

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

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
