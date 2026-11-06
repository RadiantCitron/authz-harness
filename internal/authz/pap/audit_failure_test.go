package pap_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// 계획 017 S1 — ADR 0010 시나리오 P1~P8 (요구사항에서 도출, 구현에서 베끼지 않음).

type afRig struct {
	st        *state.FileStore
	okSvc     pap.Service
	auditPath string
}

func newAFRig(t *testing.T) *afRig {
	t.Helper()
	dir := t.TempDir()
	st := mustStore(t, filepath.Join(dir, "s.json"))
	ap := filepath.Join(dir, "audit.jsonl")
	w, err := audit.NewJSONLWriter(ap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return &afRig{st: st, okSvc: pap.NewService(st, w), auditPath: ap}
}

// gateWriter 는 첫 Log 호출에서 started 를 알리고 release 가 닫힐 때까지 막은 뒤 실패한다.
type gateWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGate() *gateWriter {
	return &gateWriter{started: make(chan struct{}), release: make(chan struct{})}
}
func (g *gateWriter) Log(audit.Event) error {
	g.once.Do(func() { close(g.started) })
	<-g.release
	return errors.New("injected")
}
func (g *gateWriter) Close() error { return nil }

// failNthUpdateStore 는 n 번째 Update 호출만 실패시킨다(1-base).
type failNthUpdateStore struct {
	state.Store
	n, calls int
}

var errRollbackInjected = errors.New("rollback injected")

func (f *failNthUpdateStore) Update(fn func(*state.GrantsState) error) error {
	f.calls++
	if f.calls == f.n {
		return errRollbackInjected
	}
	return f.Store.Update(fn)
}

func mustGrant(t *testing.T, svc pap.Service, res string) *domain.Grant {
	t.Helper()
	g, err := svc.CreateGrant(context.Background(), pap.CreateGrantRequest{Subject: "w", Action: domain.ActionFileRead, Resource: res})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAF_P1_RevokeAuditFailureKeepsRevocation(t *testing.T) {
	r := newAFRig(t)
	g := mustGrant(t, r.okSvc, "a.txt")
	_, err := pap.NewService(r.st, failingWriter{}).RevokeGrant(context.Background(), g.ID)
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed || domain.ExitCodeFromError(err, 0) != domain.ExitAuditFailure {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "revoked") {
		t.Errorf("message must state the revocation was applied: %v", err)
	}
	loaded, _ := r.st.Load()
	if loaded.Grants[0].IsActive() || loaded.Grants[0].RevokedAt == nil {
		t.Fatalf("grant must stay revoked: %+v", loaded.Grants[0])
	}
}

func TestAF_P2_BumpAuditFailureKeepsEpoch(t *testing.T) {
	r := newAFRig(t)
	_, err := pap.NewService(r.st, failingWriter{}).BumpEpoch(context.Background(), "w")
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("got %v", err)
	}
	loaded, _ := r.st.Load()
	if got := loaded.Epochs.Get("w"); got != 2 {
		t.Fatalf("epoch must stay bumped to 2, got %d", got)
	}
}

func TestAF_P3_ConcurrentRevokeNotUndone(t *testing.T) {
	r := newAFRig(t)
	g := mustGrant(t, r.okSvc, "a.txt")
	gate := newGate()
	done := make(chan error, 1)
	go func() {
		_, err := pap.NewService(r.st, gate).RevokeGrant(context.Background(), g.ID)
		done <- err
	}()
	<-gate.started
	if _, err := r.okSvc.RevokeGrant(context.Background(), g.ID); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	if err := <-done; domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("got %v", err)
	}
	loaded, _ := r.st.Load()
	if loaded.Grants[0].IsActive() {
		t.Fatal("revoked grant was resurrected by rollback (R4)")
	}
}

func bumpRaceRig(t *testing.T) *afRig {
	t.Helper()
	r := newAFRig(t)
	gate := newGate()
	done := make(chan error, 1)
	go func() {
		_, err := pap.NewService(r.st, gate).BumpEpoch(context.Background(), "w")
		done <- err
	}()
	<-gate.started
	if _, err := r.okSvc.BumpEpoch(context.Background(), "w"); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	if err := <-done; domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("got %v", err)
	}
	return r
}

func TestAF_P4_ConcurrentBumpNotUndone(t *testing.T) {
	r := bumpRaceRig(t)
	loaded, _ := r.st.Load()
	if got := loaded.Epochs.Get("w"); got != 3 {
		t.Fatalf("want epoch 3, got %d (R3)", got)
	}
}

func TestAF_P5_StaleEpochDeniedAfterRace(t *testing.T) {
	r := bumpRaceRig(t)
	mustGrant(t, r.okSvc, "a.txt")
	snap, err := pip.NewService(r.st).GetSubjectSnapshot(context.Background(), "w")
	if err != nil {
		t.Fatal(err)
	}
	d := pdp.Evaluate(pdp.Request{Subject: "w", Action: domain.ActionFileRead, Resource: "a.txt", Epoch: 1}, snap)
	if d.Decision != pdp.DecisionDeny || d.Reason != domain.ReasonSubjectEpochRevoked {
		t.Fatalf("got %+v", d)
	}
}

func TestAF_P6_RetryAfterAuditRecovery(t *testing.T) {
	r := newAFRig(t)
	g := mustGrant(t, r.okSvc, "a.txt")
	if _, err := pap.NewService(r.st, failingWriter{}).RevokeGrant(context.Background(), g.ID); err == nil {
		t.Fatal("want failure")
	}
	if _, err := r.okSvc.RevokeGrant(context.Background(), g.ID); err != nil {
		t.Fatalf("retry must succeed: %v", err)
	}
	raw, _ := os.ReadFile(r.auditPath)
	if n := strings.Count(string(raw), "grant.revoked"); n != 1 {
		t.Fatalf("want 1 grant.revoked, got %d", n)
	}
}

func TestAF_P7_CreateRollbackOnAuditFailure(t *testing.T) {
	r := newAFRig(t)
	ctx := context.Background()
	fs := pap.NewService(r.st, failingWriter{})
	if _, err := fs.CreateGrant(ctx, pap.CreateGrantRequest{Subject: "w", Action: domain.ActionFileRead, Resource: "x"}); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("grant: %v", err)
	}
	if _, err := fs.CreateApproval(ctx, pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "x", TokenJTI: "j"}); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("approval: %v", err)
	}
	loaded, _ := r.st.Load()
	if len(loaded.Grants) != 0 || len(loaded.Approvals) != 0 {
		t.Fatalf("entries must be gone: %+v", loaded)
	}
}

func TestAF_P8_RollbackErrorNotSwallowed(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"grant", "approval"} {
		t.Run(name, func(t *testing.T) {
			r := newAFRig(t)
			fst := &failNthUpdateStore{Store: r.st, n: 2} // 1: 저장, 2: 되돌리기
			svc := pap.NewService(fst, failingWriter{})
			var err error
			if name == "grant" {
				_, err = svc.CreateGrant(ctx, pap.CreateGrantRequest{Subject: "w", Action: domain.ActionFileRead, Resource: "x"})
			} else {
				_, err = svc.CreateApproval(ctx, pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "x", TokenJTI: "j"})
			}
			if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
				t.Fatalf("reason: %v", err)
			}
			if !errors.Is(err, errRollbackInjected) {
				t.Errorf("rollback error missing from chain: %v", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "may remain") {
				t.Errorf("message must say the entry may remain: %v", err)
			}
		})
	}
}
