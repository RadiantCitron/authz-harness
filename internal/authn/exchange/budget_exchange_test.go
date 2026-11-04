package exchange_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

type budgetEnv struct {
	svc      *exchange.ExchangeService
	issuer   *token.Service
	verifier *token.Verifier
	ledger   *budget.FileLedger
	ledgerP  string
	clk      *mutableClock
	auditP   string
}

func newBudgetEnv(t *testing.T, withExchangeLedger, withIssuerLedger bool) *budgetEnv {
	t.Helper()
	dir := t.TempDir()
	clk := &mutableClock{t: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)}
	st, err := keys.NewFileStore(filepath.Join(dir, "p.json"), filepath.Join(dir, "j.json"))
	if err != nil {
		t.Fatal(err)
	}
	aw, err := audit.NewJSONLWriter(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aw.Close() })
	km, err := keys.NewManager(st, aw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.RotateKey(domain.AuditContext{TraceID: "s", Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	ledgerP := filepath.Join(dir, "budget_ledger.json")
	ledger, err := budget.NewFileLedger(ledgerP, clk)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := token.NewFileReplayLedger(filepath.Join(dir, "replay.json"), clk)
	if err != nil {
		t.Fatal(err)
	}
	clients := token.NewInMemoryClientRegistry()
	var iopts []token.ServiceOption
	if withIssuerLedger {
		iopts = append(iopts, token.WithBudgetLedger(ledger))
	}
	issuer := token.NewService(km, clients, aw, clk, iopts...)
	verifier := token.NewVerifier(km, replay, aw, clk)
	var eopts []exchange.Option
	if withExchangeLedger {
		eopts = append(eopts, exchange.WithBudgetLedger(ledger))
	}
	svc := exchange.NewExchangeService(issuer, verifier, clients, nil, aw, clk, eopts...)
	return &budgetEnv{svc, issuer, verifier, ledger, ledgerP, clk, filepath.Join(dir, "audit.jsonl")}
}

func (e *budgetEnv) root(t *testing.T, b *domain.Budget) *token.IssueResult {
	t.Helper()
	r, err := e.issuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "orchestrator-main", Scope: "file:read:docs/a.txt file:write:docs/b.txt",
		TTL: time.Hour, Budget: b,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("root issue: %v", err)
	}
	return r
}

func (e *budgetEnv) exch(parent, sub string, b *domain.Budget) (*exchange.ExchangeResult, error) {
	return e.svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: parent, ChildSubject: sub, Scope: "file:read:docs/a.txt",
		TTL: 30 * time.Minute, Budget: b,
	}, domain.AuditContext{})
}

func reasonOf(t *testing.T, err error, want domain.Reason, exit domain.ExitCode) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Reason != want || de.ExitCode != exit {
		t.Fatalf("want %s/%d, got %v", want, exit, err)
	}
}

func remaining(t *testing.T, l budget.Ledger, jti string) int64 {
	t.Helper()
	e, ok, err := l.Get(jti)
	if err != nil || !ok {
		t.Fatalf("Get %s: ok=%v err=%v", jti, ok, err)
	}
	return e.Remaining.MaxCalls
}

func TestBudget_RootRegistered(t *testing.T) { // TC-030-01
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 10})
	if remaining(t, e.ledger, r.Claims.JWTID) != 10 {
		t.Fatal("root not registered with 10")
	}
}

func TestBudget_ChildExceedsParentStatic(t *testing.T) { // TC-030-02
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 10})
	res, err := e.exch(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 11})
	reasonOf(t, err, domain.ReasonDelegationBudgetExceeded, 12)
	if res != nil {
		t.Fatal("no token on deny")
	}
	if remaining(t, e.ledger, r.Claims.JWTID) != 10 {
		t.Fatal("parent remaining changed")
	}
	data, _ := os.ReadFile(e.auditP)
	if !contains(data, "token.exchange.deny") {
		t.Fatal("deny audit missing")
	}
}

func TestBudget_LedgerCheckAfterStaticPass(t *testing.T) { // TC-030-03
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 10})
	if _, err := e.exch(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 6}); err != nil {
		t.Fatal(err)
	}
	if remaining(t, e.ledger, r.Claims.JWTID) != 4 {
		t.Fatal("parent remaining want 4")
	}
	res, err := e.exch(r.TokenString, "worker-02", &domain.Budget{MaxCalls: 5})
	reasonOf(t, err, domain.ReasonDelegationBudgetExceeded, 12)
	if res != nil {
		t.Fatal("no token on ledger deny")
	}
	if remaining(t, e.ledger, r.Claims.JWTID) != 4 {
		t.Fatal("failed reserve changed parent")
	}
}

func TestBudget_NoEscalationNoOrphanChild(t *testing.T) { // TC-030-04
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 10})
	_, err := e.exch(r.TokenString, "worker-01", nil)
	reasonOf(t, err, domain.ReasonDelegationBudgetExceeded, 12)

	plain, err := e.issuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "orchestrator-main", Scope: "file:read:docs/a.txt", TTL: time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.exch(plain.TokenString, "worker-01", &domain.Budget{MaxCalls: 1})
	reasonOf(t, err, domain.ReasonDelegationBudgetExceeded, 12)
}

func TestBudget_TwoHopSumConserved(t *testing.T) { // TC-030-05
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 10})
	lead, err := e.exch(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 6})
	if err != nil {
		t.Fatal(err)
	}
	w, err := e.svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: lead.TokenString, ChildSubject: "worker-02", Scope: "file:read:docs/a.txt",
		TTL: 10 * time.Minute, Budget: &domain.Budget{MaxCalls: 4},
	}, domain.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	root, l, wk := remaining(t, e.ledger, r.Claims.JWTID), remaining(t, e.ledger, lead.Claims.JWTID), remaining(t, e.ledger, w.Claims.JWTID)
	if root != 4 || l != 2 || wk != 4 || root+l+wk != 10 {
		t.Fatalf("root=%d lead=%d worker=%d", root, l, wk)
	}
}

func TestBudget_FailClosedWithoutLedger(t *testing.T) { // TC-030-06
	// 원장 없는 발급자에 예산 루트 발급
	e := newBudgetEnv(t, false, false)
	_, err := e.issuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "orchestrator-main", Scope: "file:read:docs/a.txt", TTL: time.Hour,
		Budget: &domain.Budget{MaxCalls: 3},
	}, token.IssueOptions{}, domain.AuditContext{})
	reasonOf(t, err, domain.ReasonInternalError, 16)

	// 원장 없는 교환 서비스로 예산 부모 교환 (발급자엔 원장이 있어 부모는 발급됨)
	e2 := newBudgetEnv(t, false, true)
	r := e2.root(t, &domain.Budget{MaxCalls: 3})
	res, err := e2.exch(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 1})
	reasonOf(t, err, domain.ReasonInternalError, 16)
	if res != nil {
		t.Fatal("no token")
	}
}

func TestBudget_DeletedLedgerDoesNotResurrect(t *testing.T) { // TC-030-07
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 10})
	if err := os.Remove(e.ledgerP); err != nil {
		t.Fatal(err)
	}
	_, err := e.exch(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 1})
	reasonOf(t, err, domain.ReasonDelegationBudgetExceeded, 12)
}

func TestBudget_ReplaySplit(t *testing.T) { // TC-030-08
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 2})
	opts := token.VerifyOptions{RecordReplay: true}
	for i := 0; i < 2; i++ {
		if _, err := e.verifier.VerifyToken(r.TokenString, opts, domain.AuditContext{}); err != nil {
			t.Fatalf("budget token verify #%d: %v", i+1, err)
		}
	}
	plain, err := e.issuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "orchestrator-main", Scope: "file:read:docs/a.txt", TTL: time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.verifier.VerifyToken(plain.TokenString, opts, domain.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	_, err = e.verifier.VerifyToken(plain.TokenString, opts, domain.AuditContext{})
	reasonOf(t, err, domain.ReasonTokenReplayDetected, 11)
}

func TestValidateBudgetDownscope_Table(t *testing.T) {
	b := func(c int64) *domain.Budget { return &domain.Budget{MaxCalls: c} }
	tests := []struct {
		name          string
		parent, child *domain.Budget
		deny          bool
	}{
		{"둘 다 nil", nil, nil, false},
		{"부모 nil 자식 있음", nil, b(1), true},
		{"부모 있음 자식 nil", b(5), nil, true},
		{"이내", b(5), b(5), false},
		{"초과", b(5), b(6), true},
		{"무효 자식", b(5), &domain.Budget{MaxCalls: 0}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := exchange.ValidateBudgetDownscope(tc.parent, tc.child)
			if tc.deny {
				var de *domain.Error
				if !errors.As(err, &de) || de.ExitCode == 0 {
					t.Fatalf("want deny, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func contains(b []byte, s string) bool { return len(b) > 0 && indexOf(string(b), s) >= 0 }

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
