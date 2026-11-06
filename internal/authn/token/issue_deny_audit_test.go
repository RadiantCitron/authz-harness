package token

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/domain"
)

// 계획 017 S1 — 토큰 발급 거부 감사 시나리오 T1~T7, T9 (계획 3.2에서 도출).

type captureWriter struct {
	events []audit.Event
	err    error
	calls  int
}

func (c *captureWriter) Log(e audit.Event) error {
	c.calls++
	if c.err != nil {
		return c.err
	}
	c.events = append(c.events, e)
	return nil
}
func (c *captureWriter) Close() error { return nil }

func (c *captureWriter) denies() []audit.Event {
	var out []audit.Event
	for _, e := range c.events {
		if e.Action == "token.issue.deny" {
			out = append(out, e)
		}
	}
	return out
}

const (
	orchID  = "client-orchestrator"
	orchSec = "orchestrator-secret-key-01"
)

func issueWith(t *testing.T, w audit.Writer, km keys.KeyManager, req IssueRequest) (*IssueResult, error) {
	t.Helper()
	rig := setupTestRig(t)
	if km == nil {
		km = rig.keyMgr
	}
	s := NewService(km, rig.clients, w, domain.RealClock{})
	return s.IssueToken(req, IssueOptions{}, domain.AuditContext{TraceID: "tr-1"})
}

func okReq() IssueRequest {
	return IssueRequest{ClientID: orchID, ClientSecret: orchSec, Subject: "worker-01", Scope: "file:read:docs/plan.txt"}
}

func wantOneDeny(t *testing.T, w *captureWriter, res *IssueResult, err error, reason domain.Reason) audit.Event {
	t.Helper()
	if res != nil || err == nil {
		t.Fatalf("must fail without token: res=%v err=%v", res, err)
	}
	d := w.denies()
	if len(d) != 1 {
		t.Fatalf("want exactly 1 token.issue.deny, got %d (%+v)", len(d), w.events)
	}
	if reason != "" && domain.ReasonFromError(err, "") != reason {
		t.Errorf("error reason: want %s got %v", reason, err)
	}
	if reason != "" && d[0].Reason != string(reason) {
		t.Errorf("audit reason: want %s got %s", reason, d[0].Reason)
	}
	return d[0]
}

func TestIssueDeny_T1_SubjectNotAllowed(t *testing.T) {
	w := &captureWriter{}
	req := okReq()
	req.ClientID, req.ClientSecret, req.Subject = "client-subagent", "subagent-secret-key-02", "intruder"
	res, err := issueWith(t, w, nil, req)
	wantOneDeny(t, w, res, err, domain.ReasonNoActiveGrant)
}

func TestIssueDeny_T2_EmptySubject(t *testing.T) {
	w := &captureWriter{}
	req := okReq()
	req.Subject = "  "
	res, err := issueWith(t, w, nil, req)
	wantOneDeny(t, w, res, err, domain.ReasonInvalidArguments)
}

func TestIssueDeny_T3_ClaimValidation(t *testing.T) {
	w := &captureWriter{}
	req := okReq()
	req.Budget = &domain.Budget{MaxCalls: 0}
	res, err := issueWith(t, w, nil, req)
	wantOneDeny(t, w, res, err, "")
}

type noKeyManager struct{ keys.KeyManager }

func (noKeyManager) GetActiveSigningKey() (*domain.SigningKey, error) {
	return nil, errors.New("no active key")
}

func TestIssueDeny_T4_NoActiveSigningKey(t *testing.T) {
	w := &captureWriter{}
	res, err := issueWith(t, w, noKeyManager{}, okReq())
	wantOneDeny(t, w, res, err, domain.ReasonInternalError)
}

func TestIssueDeny_T5_DenyAuditWriteFails(t *testing.T) {
	w := &captureWriter{err: errors.New("audit down")}
	req := okReq()
	req.ClientID, req.ClientSecret, req.Subject = "client-subagent", "subagent-secret-key-02", "intruder"
	res, err := issueWith(t, w, nil, req)
	if res != nil || domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("res=%v err=%v", res, err)
	}
}

func TestIssueDeny_T6_WrongSecretExactlyOnce(t *testing.T) {
	w := &captureWriter{}
	req := okReq()
	req.ClientSecret = "wrong"
	res, err := issueWith(t, w, nil, req)
	d := wantOneDeny(t, w, res, err, "")
	if d.Step != "token.issue_authn" {
		t.Errorf("step: got %s", d.Step)
	}
	if d.Reason == "" {
		t.Error("reason must be recorded")
	}
}

func TestIssueDeny_T7_PlainAuditErrorOnSuccessPath(t *testing.T) {
	w := &captureWriter{err: errors.New("plain")}
	res, err := issueWith(t, w, nil, okReq())
	if res != nil || domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if w.calls != 1 {
		t.Errorf("Log must be called once (no deny retry), got %d", w.calls)
	}
}

func TestIssueDeny_T9_NoSecretsInAudit(t *testing.T) {
	cases := map[string]func(*IssueRequest){
		"T1": func(r *IssueRequest) {
			r.ClientID, r.ClientSecret, r.Subject = "client-subagent", "subagent-secret-key-02", "intruder"
		},
		"T2": func(r *IssueRequest) { r.Subject = "" },
		"T3": func(r *IssueRequest) { r.Budget = &domain.Budget{} },
	}
	for name, mut := range cases {
		w := &captureWriter{}
		req := okReq()
		mut(&req)
		issueWith(t, w, nil, req)
		if len(w.denies()) != 1 {
			t.Fatalf("%s: want 1 deny, got %d", name, len(w.denies()))
		}
		b, _ := json.Marshal(w.events)
		for _, banned := range []string{req.ClientSecret, "eyJ"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s: audit leaks %q", name, banned)
			}
		}
	}
}

// 계획 022 T1: 1초 미만 TTL(1ns)(exp == iat)은 입력 불량이며 INTERNAL_ERROR 가 아니다.
func TestIssueDeny_P022T1_SubSecondTTLIsInvalidArguments(t *testing.T) {
	w := &captureWriter{}
	req := okReq()
	req.TTL = time.Nanosecond
	res, err := issueWith(t, w, nil, req)
	wantOneDeny(t, w, res, err, domain.ReasonInvalidArguments)
	var de *domain.Error
	if !errors.As(err, &de) || de.ExitCode != domain.ExitBadInput {
		t.Errorf("exit code: want ExitBadInput, got %v", err)
	}
}
