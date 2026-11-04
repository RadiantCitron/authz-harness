package pdp_test

import (
	"context"
	"testing"
	"time"

	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/domain"
)

var askNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func askGrant(id string, needs bool) domain.Grant {
	return domain.Grant{ID: id, Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt",
		Status: domain.GrantStatusActive, CreatedAt: askNow, RequiresApproval: needs}
}

func askApproval(id string) domain.Approval {
	return domain.Approval{ID: id, Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt",
		TokenJTI: "j1", ArgHash: domain.DataDigest([]byte("x")), CreatedAt: askNow, ExpiresAt: askNow.Add(time.Minute)}
}

func askReq() pdp.Request {
	return pdp.Request{Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt", Epoch: 1,
		TokenJTI: "j1", ArgHash: domain.DataDigest([]byte("x")), Now: askNow}
}

func askSnap(grants []domain.Grant, aps ...domain.Approval) *pip.SubjectSnapshot {
	return &pip.SubjectSnapshot{Subject: "w", CurrentEpoch: 1, ActiveGrants: grants, Approvals: aps, Timestamp: askNow}
}

func TestEvaluateAsk(t *testing.T) {
	need := []domain.Grant{askGrant("g1", true)}
	t.Run("TC-030-01 no approval", func(t *testing.T) {
		d := pdp.Evaluate(askReq(), askSnap(need))
		if d.Decision != pdp.DecisionAsk || d.Reason != domain.ReasonApprovalRequired || d.ApprovalID != "" {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("TC-030-02 valid approval", func(t *testing.T) {
		d := pdp.Evaluate(askReq(), askSnap(need, askApproval("ap-1")))
		if d.Decision != pdp.DecisionAllow || d.Reason != domain.ReasonAuthorized || d.ApprovalID != "ap-1" || d.GrantID != "g1" {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("TC-030-03 mismatch", func(t *testing.T) {
		r1 := askApproval("a")
		r1.Resource = "other.txt"
		r2 := askApproval("a")
		r2.TokenJTI = "j2"
		r3 := askApproval("a")
		r3.ArgHash = domain.DataDigest([]byte("y"))
		for i, a := range []domain.Approval{r1, r2, r3} {
			d := pdp.Evaluate(askReq(), askSnap(need, a))
			if d.Decision != pdp.DecisionAsk || d.Reason != domain.ReasonApprovalMismatch {
				t.Errorf("case %d: %+v", i, d)
			}
		}
	})
	t.Run("TC-030-04 expiry boundary", func(t *testing.T) {
		a := askApproval("a")
		r := askReq()
		r.Now = a.ExpiresAt
		d := pdp.Evaluate(r, askSnap(need, a))
		if d.Decision != pdp.DecisionAsk || d.Reason != domain.ReasonApprovalExpired {
			t.Fatalf("%+v", d)
		}
		r.Now = time.Time{}
		s := askSnap(need, a)
		s.Timestamp = a.ExpiresAt
		d = pdp.Evaluate(r, s)
		if d.Decision != pdp.DecisionAsk || d.Reason != domain.ReasonApprovalExpired {
			t.Fatalf("snapshot time fallback: %+v", d)
		}
	})
	t.Run("TC-030-05 revoke/epoch win over approval", func(t *testing.T) {
		revoked := askGrant("g1", true)
		revoked.Status = domain.GrantStatusRevoked
		s := askSnap(nil, askApproval("a"))
		s.RevokedGrants = []domain.Grant{revoked}
		if d := pdp.Evaluate(askReq(), s); d.Decision != pdp.DecisionDeny || d.Reason != domain.ReasonGrantRevoked {
			t.Fatalf("revoked: %+v", d)
		}
		r := askReq()
		r.Epoch = 2
		if d := pdp.Evaluate(r, askSnap(need, askApproval("a"))); d.Decision != pdp.DecisionDeny || d.Reason != domain.ReasonSubjectEpochRevoked {
			t.Fatalf("epoch: %+v", d)
		}
		r = askReq()
		r.Actor = &domain.ActorClaim{Subject: "parent", Epoch: 1}
		s = askSnap(need, askApproval("a"))
		s.SubjectEpochs = domain.SecurityEpochs{"parent": 2}
		if d := pdp.Evaluate(r, s); d.Decision != pdp.DecisionDeny || d.Reason != domain.ReasonSubjectEpochRevoked {
			t.Fatalf("ancestor: %+v", d)
		}
	})
	t.Run("TC-030-06 plain grant", func(t *testing.T) {
		d := pdp.Evaluate(askReq(), askSnap([]domain.Grant{askGrant("g1", false)}))
		if d.Decision != pdp.DecisionAllow || d.ApprovalID != "" {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("TC-030-07 strictest grant wins in either order", func(t *testing.T) {
		for _, gs := range [][]domain.Grant{
			{askGrant("plain", false), askGrant("need", true)},
			{askGrant("need", true), askGrant("plain", false)},
		} {
			d := pdp.Evaluate(askReq(), askSnap(gs))
			if d.Decision != pdp.DecisionAsk || d.Reason != domain.ReasonApprovalRequired {
				t.Fatalf("%+v", d)
			}
		}
	})
	t.Run("empty jti fails closed", func(t *testing.T) {
		r := askReq()
		r.TokenJTI = ""
		if d := pdp.Evaluate(r, askSnap(need, askApproval("a"))); d.Decision != pdp.DecisionAsk {
			t.Fatalf("%+v", d)
		}
	})
}

func TestDecideAskAudit(t *testing.T) { // TC-030-09
	au := &mockAudit{}
	svc := pdp.NewService(&mockPIP{snapshot: askSnap([]domain.Grant{askGrant("g1", true)})}, au)
	d, err := svc.Decide(context.Background(), askReq())
	if err != nil || d.Decision != pdp.DecisionAsk {
		t.Fatalf("%v %+v", err, d)
	}
	if len(au.events) != 1 || au.events[0].Decision != "ask" || au.events[0].Success {
		t.Fatalf("%+v", au.events)
	}
	if domain.ExitCodeForReason(d.Reason) != domain.ExitApprovalRequired {
		t.Fatal("ask must map to 18")
	}
}
