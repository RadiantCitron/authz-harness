package pap_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

type failingWriter struct{}

func (failingWriter) Log(audit.Event) error { return errors.New("injected") }
func (failingWriter) Close() error          { return nil }

func TestApprovalCreateAndList(t *testing.T) {
	svc, _, auditPath := setupTestPAP(t)
	ctx := context.Background()
	a, err := svc.CreateApproval(ctx, pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt", TokenJTI: "j1"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ExpiresAt.Sub(a.CreatedAt) != domain.DefaultApprovalTTL {
		t.Fatalf("default ttl not applied: %s", a.ExpiresAt.Sub(a.CreatedAt))
	}
	list, _ := svc.ListApprovals(ctx, "w")
	other, _ := svc.ListApprovals(ctx, "x")
	if len(list) != 1 || len(other) != 0 {
		t.Fatalf("list: %d/%d", len(list), len(other))
	}
	raw, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(raw), "approval.granted") {
		t.Fatal("approval.granted audit missing")
	}
}

func TestApprovalInvalidArgs(t *testing.T) {
	svc, statePath, _ := setupTestPAP(t)
	base := pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt", TokenJTI: "j1"}
	for name, mut := range map[string]func(*pap.CreateApprovalRequest){
		"ttl":  func(r *pap.CreateApprovalRequest) { r.TTL = 2 * time.Hour },
		"hash": func(r *pap.CreateApprovalRequest) { r.ArgHash = "sha256:XYZ" },
		"jti":  func(r *pap.CreateApprovalRequest) { r.TokenJTI = "" },
	} {
		r := base
		mut(&r)
		if _, err := svc.CreateApproval(context.Background(), r); domain.ExitCodeFromError(err, 0) != domain.ExitBadInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	st, _ := mustStore(t, statePath).Load()
	if len(st.Approvals) != 0 {
		t.Fatal("ledger must be unchanged")
	}
}

func mustStore(t *testing.T, p string) *state.FileStore {
	t.Helper()
	s, err := state.NewFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApprovalAuditFailure(t *testing.T) { // TC-020-06
	st := mustStore(t, filepath.Join(t.TempDir(), "s.json"))
	svc := pap.NewService(st, failingWriter{})
	_, err := svc.CreateApproval(context.Background(), pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt", TokenJTI: "j1"})
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed || domain.ExitCodeFromError(err, 0) != domain.ExitAuditFailure {
		t.Fatalf("got %v", err)
	}
}

func TestApprovalGrantRequiresApproval(t *testing.T) {
	svc, _, _ := setupTestPAP(t)
	g, err := svc.CreateGrant(context.Background(), pap.CreateGrantRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt", RequiresApproval: true})
	if err != nil || !g.RequiresApproval {
		t.Fatalf("%v %+v", err, g)
	}
}
