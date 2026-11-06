package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/domain"
)

// 계획 022 L1: 잠금 파일을 열 수 없으면 Log·RecoverIncompleteTail 모두 AUDIT_LOG_FAILED.
func TestAuditLock_L1_UnopenableLockFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := os.Mkdir(path+".lock", 0700); err != nil { // 디렉터리라 파일로 열 수 없다
		t.Fatal(err)
	}
	if err := w.Log(Event{TraceID: "t", Action: "x"}); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Errorf("Log: want AUDIT_LOG_FAILED, got %v", err)
	}
	if _, err := RecoverIncompleteTail(path, domain.RealClock{}); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Errorf("Recover: want AUDIT_LOG_FAILED, got %v", err)
	}
}

// 계획 022 L2: 잠금 안에서 난 오류는 덮이지 않는다.
func TestAuditLock_L2_CallbackErrorPassesThrough(t *testing.T) {
	want := domain.NewError(domain.ReasonInternalError, "boom", nil)
	err := withAuditLock(filepath.Join(t.TempDir(), "a.jsonl"), func() error { return want })
	if !errors.Is(err, want) {
		t.Errorf("want original error, got %v", err)
	}
}
