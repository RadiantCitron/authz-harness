package keys

import (
	"errors"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// 계획 019 S1 — 키 관리 거부·재폐기 감사 시나리오 A1~A4 (계획 2장에서 도출).

type captureAudit struct{ events []audit.Event }

func (c *captureAudit) Log(e audit.Event) error { c.events = append(c.events, e); return nil }
func (c *captureAudit) Close() error            { return nil }

func (c *captureAudit) byAction(action string) []audit.Event {
	var out []audit.Event
	for _, e := range c.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

var denyCtx = domain.AuditContext{TraceID: "tr-1", Actor: "operator", Reason: "test"}

func newCapturedManager(t *testing.T) (*Manager, *captureAudit) {
	t.Helper()
	store, _, _, _ := setupTestStore(t)
	w := &captureAudit{}
	m, err := NewManager(store, w)
	if err != nil {
		t.Fatal(err)
	}
	return m, w
}

// A1: 없는 kid 폐기는 key.revoke.deny 1건을 남긴다.
func TestRevokeKey_UnknownKidRecordsDeny(t *testing.T) {
	m, w := newCapturedManager(t)
	if err := m.RevokeKey("no-such-kid", denyCtx); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	got := w.byAction("key.revoke.deny")
	if len(got) != 1 {
		t.Fatalf("expected 1 key.revoke.deny, got %d", len(got))
	}
	if got[0].Success || got[0].Decision != "deny" || got[0].Reason == "" || got[0].TraceID != "tr-1" {
		t.Fatalf("unexpected deny event: %+v", got[0])
	}
}

// A2: 이미 retired인 키 재폐기는 성공하고 key.revoke.noop 1건만 남긴다 (key.revoked 추가 없음).
func TestRevokeKey_AlreadyRetiredRecordsNoop(t *testing.T) {
	m, w := newCapturedManager(t)
	active, err := m.GetActiveSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeKey(active.KID, denyCtx); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeKey(active.KID, denyCtx); err != nil {
		t.Fatalf("re-revoke must stay idempotent: %v", err)
	}
	if n := len(w.byAction("key.revoked")); n != 1 {
		t.Fatalf("key.revoked must stay 1, got %d", n)
	}
	noop := w.byAction("key.revoke.noop")
	if len(noop) != 1 || !noop[0].Success {
		t.Fatalf("expected 1 successful key.revoke.noop, got %+v", noop)
	}
	if noop[0].Metadata["kid"] != active.KID {
		t.Fatalf("noop metadata must carry kid, got %+v", noop[0].Metadata)
	}
}

// A3: 정상 회전·폐기의 기록은 그대로다.
func TestKeyManager_NormalOperationsKeepRecords(t *testing.T) {
	m, w := newCapturedManager(t)
	old, _ := m.GetActiveSigningKey()
	if _, err := m.RotateKey(denyCtx); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeKey(old.KID, denyCtx); err != nil {
		t.Fatal(err)
	}
	if len(w.byAction("key.rotated")) != 1 || len(w.byAction("key.revoked")) != 1 {
		t.Fatalf("expected 1 key.rotated and 1 key.revoked, got %+v", w.events)
	}
	if len(w.byAction("key.revoke.deny"))+len(w.byAction("key.revoke.noop"))+len(w.byAction("key.rotate.deny")) != 0 {
		t.Fatalf("normal operations must not record deny/noop: %+v", w.events)
	}
}

// A4: 빈 kid도 거부 기록을 남긴다.
func TestRevokeKey_EmptyKidRecordsDeny(t *testing.T) {
	m, w := newCapturedManager(t)
	if err := m.RevokeKey("", denyCtx); err == nil {
		t.Fatal("expected error for empty kid")
	}
	if n := len(w.byAction("key.revoke.deny")); n != 1 {
		t.Fatalf("expected 1 key.revoke.deny, got %d", n)
	}
}

// A5: 거부 기록 쓰기가 실패하면 원래 거부 대신 AUDIT_LOG_FAILED (계획 D-04).
func TestRevokeKey_DenyAuditFailure(t *testing.T) {
	store, _, _, _ := setupTestStore(t)
	if _, err := NewManager(store, nil); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(store, failingAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeKey("no-such-kid", denyCtx); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("expected AUDIT_LOG_FAILED, got %v", err)
	}
}

// 계획 022 K1: 폐기 입력 오류는 도메인 오류(INVALID_ARGUMENTS/ExitBadInput)이며 sentinel 은 유지된다.
func TestRevokeKey_InputErrorsAreDomainErrors(t *testing.T) {
	m, _ := newCapturedManager(t)
	for name, c := range map[string]struct {
		kid  string
		want error
	}{"empty": {"", errEmptyKID}, "unknown": {"no-such-kid", ErrKeyNotFound}} {
		err := m.RevokeKey(c.kid, denyCtx)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: sentinel lost: %v", name, err)
		}
		if domain.ReasonFromError(err, "") != domain.ReasonInvalidArguments || domain.ExitCodeFromError(err, domain.ExitInternalError) != domain.ExitBadInput {
			t.Errorf("%s: want INVALID_ARGUMENTS/ExitBadInput, got %v", name, err)
		}
	}
}
