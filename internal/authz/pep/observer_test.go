package pep_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
	"authz-harness/internal/observe"
)

type panicAllObserver struct{}

func (panicAllObserver) OnStageStart(context.Context, string, string, ...observe.Attr) { panic("x") }
func (panicAllObserver) OnStageEnd(context.Context, string, string, bool, ...observe.Attr) {
	panic("x")
}
func (panicAllObserver) OnExecutionEnd(context.Context, string, bool, ...observe.Attr) { panic("x") }
func (panicAllObserver) OnError(context.Context, string, string, ...observe.Attr)      { panic("x") }

type recObserver struct {
	observe.NoopObserver
	mu     sync.Mutex
	errors []string
}

func (r *recObserver) OnError(_ context.Context, _ string, msg string, _ ...observe.Attr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, msg)
}

type refundFailLedger struct{ budget.Ledger }

func (refundFailLedger) Consume(string, int64, int64, int64) error { return nil }
func (refundFailLedger) Refund(string, int64, int64, int64) error  { return errors.New("refund boom") }

func obsStubs(withBudget bool) (*stubVerifier, *stubPDP, *stubJail, *stubAuditWriter) {
	claims := domain.TokenClaims{Subject: "w", JWTID: "jti-1", Scope: "file:write file:read", Epoch: 1}
	if withBudget {
		claims.Budget = &domain.Budget{MaxCalls: 5, MaxWriteBytes: 10}
	}
	return &stubVerifier{claimsToReturn: &domain.VerifiedClaims{Claims: claims}},
		&stubPDP{decisionToReturn: &pdp.Decision{Decision: pdp.DecisionAllow, Reason: domain.ReasonAuthorized, GrantID: "g"}},
		&stubJail{}, &stubAuditWriter{}
}

func TestObserver_NoopAndNilKeepVerdict(t *testing.T) { // TC-010-01
	for name, o := range map[string]observe.Observer{"nil": nil, "noop": observe.NoopObserver{}} {
		t.Run(name, func(t *testing.T) {
			v, p, j, a := obsStubs(false)
			gw, err := pep.NewGateway(pep.Config{Verifier: v, PDP: p, Jail: j, AuditWriter: a, Observer: o})
			if err != nil {
				t.Fatal(err)
			}
			r, _ := gw.Execute(context.Background(), pep.Request{Token: "t", Action: domain.ActionFileRead, Resource: "a.txt"})
			if !r.Allowed || r.ExitCode != domain.ExitSuccess || len(a.events) == 0 {
				t.Fatalf("allow: %+v events=%d", r, len(a.events))
			}
			v.errToReturn = errors.New("bad token")
			r, _ = gw.Execute(context.Background(), pep.Request{Token: "t", Action: domain.ActionFileRead, Resource: "a.txt"})
			if r.Allowed || r.ExitCode == domain.ExitSuccess {
				t.Fatalf("deny expected: %+v", r)
			}
		})
	}
}

func TestObserver_PanicDoesNotStopVerdict(t *testing.T) { // TC-010-04
	v, p, j, a := obsStubs(false)
	gw, _ := pep.NewGateway(pep.Config{Verifier: v, PDP: p, Jail: j, AuditWriter: a, Observer: panicAllObserver{}})
	r, err := gw.Execute(context.Background(), pep.Request{Token: "t", Action: domain.ActionFileRead, Resource: "a.txt"})
	if err != nil || !r.Allowed || len(a.events) == 0 {
		t.Fatalf("r=%+v err=%v events=%d", r, err, len(a.events))
	}
}

func TestObserver_RefundFailureReportedOnce(t *testing.T) { // TC-010-05
	v, p, j, a := obsStubs(true)
	a.errToReturn = errors.New("audit down")
	rec := &recObserver{}
	gw, _ := pep.NewGateway(pep.Config{Verifier: v, PDP: p, Jail: j, AuditWriter: a, Observer: rec, BudgetLedger: refundFailLedger{}})
	r, _ := gw.Execute(context.Background(), pep.Request{Token: "t", Action: domain.ActionFileWrite, Resource: "a.txt", Data: []byte("abc")})
	if r.Allowed {
		t.Fatalf("expected deny: %+v", r)
	}
	n := 0
	for _, m := range rec.errors {
		if m == "failed to refund budget" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("refund error reports=%d all=%v", n, rec.errors)
	}
}

func TestStageObserver_PanicNotSwallowed(t *testing.T) { // TC-010-06
	v, p, j, a := obsStubs(false)
	gw, _ := pep.NewGateway(pep.Config{Verifier: v, PDP: p, Jail: j, AuditWriter: a, StageObserver: func(pep.Stage) { panic("hook") }})
	defer func() {
		if recover() == nil {
			t.Fatal("StageObserver panic must propagate")
		}
	}()
	_, _ = gw.Execute(context.Background(), pep.Request{Token: "t", Action: domain.ActionFileRead, Resource: "a.txt"})
}
