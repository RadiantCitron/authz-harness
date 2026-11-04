package token

import (
	"errors"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

type failWriter struct{}

func (failWriter) Log(audit.Event) error { return errors.New("audit down") }
func (failWriter) Close() error          { return nil }

func TestAuditFailClosed_Verifier(t *testing.T) { // TC-020-02, TC-020-03①
	rig := setupTestRig(t)
	res, err := rig.issuer.IssueToken(IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Scope: "file:read:docs/plan.txt", Audience: "authz-service", TTL: time.Hour, Epoch: 1,
	}, IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(rig.keyMgr, rig.replayLedger, failWriter{}, domain.RealClock{})

	claims, err := v.VerifyToken(res.TokenString, VerifyOptions{ExpectedAudience: "authz-service"}, domain.AuditContext{})
	if claims != nil || domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("valid token must fail closed: claims=%v err=%v", claims, err)
	}

	bad, err := rig.issuer.IssueToken(IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Scope: "file:read:docs/plan.txt",
	}, IssueOptions{TamperAlgNone: true}, domain.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.VerifyToken(bad.TokenString, VerifyOptions{}, domain.AuditContext{})
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("deny path must report audit failure: %v", err)
	}
}

func TestAuditFailClosed_IssuerAuthFailure(t *testing.T) { // TC-020-03②
	rig := setupTestRig(t)
	s := NewService(rig.keyMgr, rig.clients, failWriter{}, domain.RealClock{})
	_, err := s.IssueToken(IssueRequest{ClientID: "client-orchestrator", ClientSecret: "wrong", Subject: "w", Scope: "file:read:a"}, IssueOptions{}, domain.AuditContext{})
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("got %v", err)
	}
}
