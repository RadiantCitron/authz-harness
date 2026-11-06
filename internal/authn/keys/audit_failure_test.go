package keys

import (
	"errors"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// failingAudit 은 모든 감사 쓰기가 실패하는 주입용 Writer 다.
type failingAudit struct{}

func (failingAudit) Log(audit.Event) error { return errors.New("injected") }
func (failingAudit) Close() error          { return nil }

// 계획 018 K1: 회전 뒤 감사가 실패해도 회전은 유지되고 AUDIT_LOG_FAILED 로 알린다.
func TestKeyManager_RotateAuditFailureKeepsRotation(t *testing.T) {
	store, _, _, _ := setupTestStore(t)
	okMgr, err := NewManager(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := okMgr.GetActiveSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	failMgr, err := NewManager(store, failingAudit{})
	if err != nil {
		t.Fatalf("existing key ring must not bootstrap: %v", err)
	}
	if _, err := failMgr.RotateKey(domain.AuditContext{TraceID: "t", Actor: "a"}); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("expected AUDIT_LOG_FAILED, got %v", err)
	}

	after, err := okMgr.GetActiveSigningKey()
	if err != nil {
		t.Fatalf("expected an active key after failed audit: %v", err)
	}
	if after.KID == before.KID {
		t.Fatalf("rotation must remain applied, active kid unchanged: %s", after.KID)
	}
	if _, err := okMgr.GetVerificationKey(before.KID); err != nil {
		t.Fatalf("old key must stay verify-only, got %v", err)
	}
}

// 계획 018 K2: 폐기 뒤 감사가 실패해도 폐기는 유지된다 (ADR 0010: 줄임은 되돌리지 않는다).
func TestKeyManager_RevokeAuditFailureKeepsRevocation(t *testing.T) {
	store, _, _, _ := setupTestStore(t)
	okMgr, err := NewManager(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	active, err := okMgr.GetActiveSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	failMgr, err := NewManager(store, failingAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err := failMgr.RevokeKey(active.KID, domain.AuditContext{TraceID: "t", Actor: "a"}); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("expected AUDIT_LOG_FAILED, got %v", err)
	}
	if _, err := okMgr.GetVerificationKey(active.KID); !errors.Is(err, ErrKeyRetired) {
		t.Fatalf("revoked key must stay retired, got %v", err)
	}
}

// 계획 018 K3: 최초 키 부트스트랩의 감사 실패는 AUDIT_LOG_FAILED 이며 키 저장은 남는다(한계 고정).
func TestNewManager_BootstrapAuditFailureReason(t *testing.T) {
	store, _, _, _ := setupTestStore(t)
	if _, err := NewManager(store, failingAudit{}); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("expected AUDIT_LOG_FAILED, got %v", err)
	}
	st, err := store.LoadPrivate()
	if err != nil || st == nil || len(st.Keys) != 1 {
		t.Fatalf("bootstrap key must remain stored, got %+v (err=%v)", st, err)
	}
}
