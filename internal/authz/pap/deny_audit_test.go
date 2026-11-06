package pap_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
)

// 계획 019 S1 — PAP 거부 감사 시나리오 P1~P4, N1 (계획 2장에서 도출).

type captureWriter struct{ events []audit.Event }

func (c *captureWriter) Log(e audit.Event) error { c.events = append(c.events, e); return nil }
func (c *captureWriter) Close() error            { return nil }

func (c *captureWriter) byAction(action string) []audit.Event {
	var out []audit.Event
	for _, e := range c.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func newDenyRig(t *testing.T) (pap.Service, *captureWriter, func() int) {
	t.Helper()
	st := mustStore(t, filepath.Join(t.TempDir(), "s.json"))
	w := &captureWriter{}
	count := func() int {
		loaded, err := st.Load()
		if err != nil {
			t.Fatal(err)
		}
		return len(loaded.Grants) + len(loaded.Approvals)
	}
	return pap.NewService(st, w), w, count
}

func assertOneDeny(t *testing.T, w *captureWriter, action string) audit.Event {
	t.Helper()
	got := w.byAction(action)
	if len(got) != 1 {
		t.Fatalf("expected 1 %s, got %d (events=%+v)", action, len(got), w.events)
	}
	e := got[0]
	if e.Success || e.Decision != "deny" || e.Reason == "" {
		t.Fatalf("unexpected deny event: %+v", e)
	}
	return e
}

// P1: 검증 실패 CreateGrant → grant.create.deny 1건, 원장 불변.
func TestPAP_CreateGrantValidationFailureRecordsDeny(t *testing.T) {
	svc, w, count := newDenyRig(t)
	_, err := svc.CreateGrant(context.Background(), pap.CreateGrantRequest{Subject: "", Action: domain.ActionFileRead, Resource: "a.txt"})
	if domain.ReasonFromError(err, "") != domain.ReasonInvalidArguments {
		t.Fatalf("expected INVALID_ARGUMENTS, got %v", err)
	}
	assertOneDeny(t, w, "grant.create.deny")
	if count() != 0 {
		t.Fatal("ledger must stay empty")
	}
}

// P2: 빈 ID·없는 ID RevokeGrant → grant.revoke.deny.
func TestPAP_RevokeGrantFailureRecordsDeny(t *testing.T) {
	for _, id := range []string{"", "grant-missing"} {
		svc, w, _ := newDenyRig(t)
		if _, err := svc.RevokeGrant(context.Background(), id); domain.ReasonFromError(err, "") != domain.ReasonInvalidArguments {
			t.Fatalf("id=%q: expected INVALID_ARGUMENTS, got %v", id, err)
		}
		assertOneDeny(t, w, "grant.revoke.deny")
	}
}

// P3: 잘못된 TTL·ArgHash·필수값 CreateApproval → approval.create.deny.
func TestPAP_CreateApprovalFailureRecordsDeny(t *testing.T) {
	base := pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt", TokenJTI: "j1"}
	bad := map[string]pap.CreateApprovalRequest{}
	r := base
	r.TTL = -1
	bad["ttl"] = r
	r = base
	r.ArgHash = "not-a-hash"
	bad["arghash"] = r
	r = base
	r.TokenJTI = ""
	bad["jti"] = r
	for name, req := range bad {
		svc, w, count := newDenyRig(t)
		if _, err := svc.CreateApproval(context.Background(), req); domain.ReasonFromError(err, "") != domain.ReasonInvalidArguments {
			t.Fatalf("%s: expected INVALID_ARGUMENTS, got %v", name, err)
		}
		assertOneDeny(t, w, "approval.create.deny")
		if count() != 0 {
			t.Fatalf("%s: ledger must stay empty", name)
		}
	}
}

// P5: 빈 주체 BumpEpoch → epoch.bump.deny.
func TestPAP_BumpEpochEmptySubjectRecordsDeny(t *testing.T) {
	svc, w, _ := newDenyRig(t)
	if _, err := svc.BumpEpoch(context.Background(), "  "); domain.ReasonFromError(err, "") != domain.ReasonInvalidArguments {
		t.Fatalf("expected INVALID_ARGUMENTS, got %v", err)
	}
	assertOneDeny(t, w, "epoch.bump.deny")
}

// P4: 거부 기록 쓰기가 실패하면 AUDIT_LOG_FAILED, 원장 불변.
func TestPAP_DenyAuditFailure(t *testing.T) {
	st := mustStore(t, filepath.Join(t.TempDir(), "s.json"))
	svc := pap.NewService(st, failingWriter{})
	_, err := svc.CreateGrant(context.Background(), pap.CreateGrantRequest{Subject: "", Action: domain.ActionFileRead, Resource: "a.txt"})
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed || domain.ExitCodeFromError(err, 0) != domain.ExitAuditFailure {
		t.Fatalf("expected AUDIT_LOG_FAILED/15, got %v", err)
	}
	loaded, _ := st.Load()
	if len(loaded.Grants) != 0 {
		t.Fatal("ledger must stay empty")
	}
}

// N1: 거부 기록에는 사용자가 넣은 원시 문자열이 들어가지 않는다.
func TestPAP_DenyEventOmitsRawInput(t *testing.T) {
	svc, w, _ := newDenyRig(t)
	const leak = "leak-subject-7f3a"
	if _, err := svc.CreateGrant(context.Background(), pap.CreateGrantRequest{Subject: leak, Action: domain.ActionFileRead, Resource: ""}); err == nil {
		t.Fatal("expected validation error")
	}
	e := assertOneDeny(t, w, "grant.create.deny")
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), leak) {
		t.Fatalf("deny event leaks raw input: %s", raw)
	}
}
