package budget

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authz-harness/internal/domain"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var base = time.Unix(1_800_000_000, 0)

func newLedger(t *testing.T, path string, now time.Time) *FileLedger {
	t.Helper()
	l, err := NewFileLedger(path, fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func wantReason(t *testing.T, err error, reason domain.Reason, exit domain.ExitCode) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Reason != reason || de.ExitCode != exit {
		t.Fatalf("want %s/%d, got %v", reason, exit, err)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("BUDGET_HELPER") == "1" {
		l, err := NewFileLedger(os.Getenv("BUDGET_PATH"), nil)
		if err != nil {
			os.Exit(2)
		}
		if err := l.Consume("root", 1, 0, 0); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestConsume_ConcurrentGoroutines(t *testing.T) { // TC-020-01
	l := newLedger(t, filepath.Join(t.TempDir(), "b.json"), base)
	if err := l.Init("root", domain.Budget{MaxCalls: 3}, base.Unix()+3600); err != nil {
		t.Fatal(err)
	}
	var ok, denied atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := l.Consume("root", 1, 0, 0)
			var de *domain.Error
			switch {
			case err == nil:
				ok.Add(1)
			case errors.As(err, &de) && de.Reason == domain.ReasonBudgetExhausted:
				denied.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 3 || denied.Load() != 7 {
		t.Fatalf("ok=%d denied=%d", ok.Load(), denied.Load())
	}
	e, _, _ := l.Get("root")
	if e.Remaining.MaxCalls != 0 {
		t.Fatalf("remaining=%d", e.Remaining.MaxCalls)
	}
}

func TestConsume_MultiProcess(t *testing.T) { // TC-020-02
	path := filepath.Join(t.TempDir(), "b.json")
	l := newLedger(t, path, time.Now())
	if err := l.Init("root", domain.Budget{MaxCalls: 3}, time.Now().Unix()+3600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0])
			cmd.Env = append(os.Environ(), "BUDGET_HELPER=1", "BUDGET_PATH="+path)
			err := cmd.Run()
			if err == nil {
				ok.Add(1)
			} else if ee := (*exec.ExitError)(nil); !errors.As(err, &ee) || ee.ExitCode() != 1 {
				t.Errorf("helper failed unexpectedly: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 3 {
		t.Fatalf("successful processes=%d", ok.Load())
	}
	e, _, _ := l.Get("root")
	if e.Remaining.MaxCalls != 0 {
		t.Fatalf("remaining=%d", e.Remaining.MaxCalls)
	}
}

func TestReclaimExpiredChild(t *testing.T) { // TC-020-03
	path := filepath.Join(t.TempDir(), "b.json")
	l := newLedger(t, path, base)
	if err := l.Init("root", domain.Budget{MaxCalls: 10}, base.Unix()+3600); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("root", "c1", domain.Budget{MaxCalls: 4}, base.Unix()+60); err != nil {
		t.Fatal(err)
	}
	if err := l.Consume("c1", 1, 0, 0); err != nil {
		t.Fatal(err)
	}
	later := newLedger(t, path, base.Add(120*time.Second))
	if err := later.Reserve("root", "c2", domain.Budget{MaxCalls: 8}, base.Unix()+3600); err != nil {
		t.Fatalf("reserve after reclaim: %v", err)
	}
	root, _, _ := later.Get("root")
	if root.Remaining.MaxCalls != 1 { // 6 + 3 - 8
		t.Fatalf("root remaining=%d want 1", root.Remaining.MaxCalls)
	}
	c1, _, _ := later.Get("c1")
	if !c1.Reclaimed || c1.Remaining.MaxCalls != 0 {
		t.Fatalf("c1=%+v", c1)
	}
	wantReason(t, later.Consume("c1", 1, 0, 0), domain.ReasonBudgetExhausted, domain.ExitAuthzDenied)
}

func TestReclaimDeepChain(t *testing.T) { // 손자 → 자식 → 루트 한 트랜잭션
	path := filepath.Join(t.TempDir(), "b.json")
	l := newLedger(t, path, base)
	_ = l.Init("root", domain.Budget{MaxCalls: 10}, base.Unix()+3600)
	_ = l.Reserve("root", "c", domain.Budget{MaxCalls: 6}, base.Unix()+60)
	if err := l.Reserve("c", "g", domain.Budget{MaxCalls: 4}, base.Unix()+60); err != nil {
		t.Fatal(err)
	}
	later := newLedger(t, path, base.Add(61*time.Second))
	if err := later.Refund("root", 0, 0, 0); err != nil { // 쓰기 트랜잭션으로 회수 유발
		t.Fatal(err)
	}
	root, _, _ := later.Get("root")
	if root.Remaining.MaxCalls != 10 {
		t.Fatalf("root remaining=%d want 10", root.Remaining.MaxCalls)
	}
}

func TestByteLimits(t *testing.T) { // TC-020-04
	l := newLedger(t, filepath.Join(t.TempDir(), "b.json"), base)
	_ = l.Init("nolimit", domain.Budget{MaxCalls: 5}, base.Unix()+60)
	if err := l.Consume("nolimit", 1, 1000, 1000); err != nil {
		t.Fatalf("no byte limit must pass: %v", err)
	}
	_ = l.Init("w", domain.Budget{MaxCalls: 5, MaxWriteBytes: 20}, base.Unix()+60)
	for i := 0; i < 2; i++ {
		if err := l.Consume("w", 1, 0, 10); err != nil {
			t.Fatal(err)
		}
	}
	wantReason(t, l.Consume("w", 1, 0, 1), domain.ReasonBudgetExhausted, domain.ExitAuthzDenied)
	e, _, _ := l.Get("w")
	if e.Remaining.MaxCalls != 3 || e.Remaining.MaxWriteBytes != 0 {
		t.Fatalf("failed consume must not change state: %+v", e.Remaining)
	}
}

func TestReserve_Denied(t *testing.T) { // TC-020-05, 06, 중복, 초과
	l := newLedger(t, filepath.Join(t.TempDir(), "b.json"), base)
	_ = l.Init("p", domain.Budget{MaxCalls: 5, MaxWriteBytes: 20}, base.Unix()+60)
	d := domain.ReasonDelegationBudgetExceeded
	wantReason(t, l.Reserve("p", "c", domain.Budget{MaxCalls: 1}, base.Unix()+60), d, 12)
	wantReason(t, l.Reserve("none", "c", domain.Budget{MaxCalls: 1}, base.Unix()+60), d, 12)
	wantReason(t, l.Reserve("p", "c", domain.Budget{MaxCalls: 6, MaxWriteBytes: 1}, base.Unix()+60), d, 12)
	wantReason(t, l.Reserve("p", "c", domain.Budget{MaxCalls: 1, MaxWriteBytes: 21}, base.Unix()+60), d, 12)
	if err := l.Reserve("p", "c", domain.Budget{MaxCalls: 1, MaxWriteBytes: 5}, base.Unix()+60); err != nil {
		t.Fatal(err)
	}
	wantReason(t, l.Reserve("p", "c", domain.Budget{MaxCalls: 1, MaxWriteBytes: 5}, base.Unix()+60), d, 12)
	wantReason(t, l.Init("p", domain.Budget{MaxCalls: 9}, base.Unix()+60), d, 12)
	wantReason(t, l.Init("bad", domain.Budget{MaxCalls: 0}, base.Unix()+60), domain.ReasonInvalidArguments, 14)
	wantReason(t, l.Consume("ghost", 1, 0, 0), domain.ReasonBudgetExhausted, 12)
	p, _, _ := l.Get("p")
	if p.Remaining.MaxCalls != 4 || p.Remaining.MaxWriteBytes != 15 {
		t.Fatalf("parent=%+v", p.Remaining)
	}
}

func TestCorruptLedgerFailClosed(t *testing.T) { // TC-020-07
	path := filepath.Join(t.TempDir(), "b.json")
	junk := []byte("{not json")
	if err := os.WriteFile(path, junk, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileLedger(path, fixedClock{base}); err == nil {
		t.Fatal("corrupt ledger must fail construction")
	}
	// 정상 생성 후 파일을 손상시켜 런타임 손상을 모사
	bad := newLedger(t, filepath.Join(t.TempDir(), "x.json"), base)
	if err := os.WriteFile(bad.store.FilePath(), junk, 0644); err != nil {
		t.Fatal(err)
	}
	wantReason(t, bad.Consume("root", 1, 0, 0), domain.ReasonInternalError, 16)
	wantReason(t, bad.Init("root", domain.Budget{MaxCalls: 1}, 1), domain.ReasonInternalError, 16)
	got, _ := os.ReadFile(bad.store.FilePath())
	if string(got) != string(junk) {
		t.Fatalf("file modified: %s", got)
	}
}

func TestRefund(t *testing.T) { // TC-020-08
	path := filepath.Join(t.TempDir(), "b.json")
	l := newLedger(t, path, base)
	_ = l.Init("root", domain.Budget{MaxCalls: 5, MaxWriteBytes: 20}, base.Unix()+3600)
	if err := l.Consume("root", 1, 0, 10); err != nil {
		t.Fatal(err)
	}
	if err := l.Refund("root", 1, 0, 10); err != nil {
		t.Fatal(err)
	}
	e, _, _ := l.Get("root")
	if e.Remaining != e.Initial {
		t.Fatalf("not restored: %+v", e.Remaining)
	}
	_ = l.Refund("root", 3, 0, 99) // Initial 초과 방지
	e, _, _ = l.Get("root")
	if e.Remaining != e.Initial {
		t.Fatalf("exceeded initial: %+v", e.Remaining)
	}
	// 회수된 엔트리는 무시
	_ = l.Reserve("root", "c", domain.Budget{MaxCalls: 2, MaxWriteBytes: 5}, base.Unix()+60)
	later := newLedger(t, path, base.Add(90*time.Second))
	if err := later.Refund("c", 2, 0, 5); err != nil {
		t.Fatal(err)
	}
	c, _, _ := later.Get("c")
	if c.Remaining.MaxCalls != 0 {
		t.Fatalf("reclaimed refund changed state: %+v", c)
	}
	wantReason(t, later.Refund("ghost", 1, 0, 0), domain.ReasonInternalError, 16)
}

// 계획 022 B1: addCapped 는 한도가 있는 필드만 더하고 initial 을 넘기지 않는다.
func TestAddCapped(t *testing.T) {
	cases := []struct {
		name                string
		rem, delta, initial domain.Budget
		want                domain.Budget
	}{
		{"한도 없음: 바이트 불변", domain.Budget{MaxCalls: 1}, domain.Budget{MaxCalls: 2, MaxReadBytes: 9, MaxWriteBytes: 9}, domain.Budget{MaxCalls: 5}, domain.Budget{MaxCalls: 3}},
		{"한도 있음: 더함", domain.Budget{MaxCalls: 1, MaxReadBytes: 1, MaxWriteBytes: 1}, domain.Budget{MaxCalls: 1, MaxReadBytes: 2, MaxWriteBytes: 3}, domain.Budget{MaxCalls: 9, MaxReadBytes: 9, MaxWriteBytes: 9}, domain.Budget{MaxCalls: 2, MaxReadBytes: 3, MaxWriteBytes: 4}},
		{"상한 초과는 잘림", domain.Budget{MaxCalls: 4, MaxReadBytes: 4, MaxWriteBytes: 4}, domain.Budget{MaxCalls: 9, MaxReadBytes: 9, MaxWriteBytes: 9}, domain.Budget{MaxCalls: 5, MaxReadBytes: 6, MaxWriteBytes: 7}, domain.Budget{MaxCalls: 5, MaxReadBytes: 6, MaxWriteBytes: 7}},
	}
	for _, c := range cases {
		if got := addCapped(c.rem, c.delta, c.initial); got != c.want {
			t.Errorf("%s: want %+v got %+v", c.name, c.want, got)
		}
	}
}
