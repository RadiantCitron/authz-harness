package app_test

import (
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/app"
)

type mockClock struct {
	now time.Time
}

func (m mockClock) Now() time.Time {
	return m.now
}

// TC-010-01: BuildStack으로 스택 생성 후 유효성 검증 및 Close() 정상 동작
func TestBuildStack_ValidationAndClose(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := app.AppConfig{
		StatePath:    filepath.Join(tmpDir, "state.json"),
		PrivKeyPath:  filepath.Join(tmpDir, "keys_priv.json"),
		PubJWKSPath:  filepath.Join(tmpDir, "keys_pub.json"),
		ReplayPath:   filepath.Join(tmpDir, "replay.json"),
		AuditPath:    filepath.Join(tmpDir, "audit.jsonl"),
		WorkspaceDir: filepath.Join(tmpDir, "workspace"),
		Clock:        mockClock{now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)},
	}

	stack, err := app.BuildStack(cfg)
	if err != nil {
		t.Fatalf("BuildStack failed: %v", err)
	}
	if stack == nil {
		t.Fatal("expected non-nil AppStack")
	}

	// 모든 컴포넌트 유효성 검증
	if stack.AuditWriter == nil {
		t.Error("AuditWriter is nil")
	}
	if stack.KeyStore == nil {
		t.Error("KeyStore is nil")
	}
	if stack.KeyManager == nil {
		t.Error("KeyManager is nil")
	}
	if stack.TokenIssuer == nil {
		t.Error("TokenIssuer is nil")
	}
	if stack.TokenVerifier == nil {
		t.Error("TokenVerifier is nil")
	}
	if stack.ClientReg == nil {
		t.Error("ClientReg is nil")
	}
	if stack.ReplayLedger == nil {
		t.Error("ReplayLedger is nil")
	}
	if stack.StateStore == nil {
		t.Error("StateStore is nil")
	}
	if stack.PAP == nil {
		t.Error("PAP is nil")
	}
	if stack.PIP == nil {
		t.Error("PIP is nil")
	}
	if stack.PDP == nil {
		t.Error("PDP is nil")
	}
	if stack.Jail == nil {
		t.Error("Jail is nil")
	}
	if stack.PEP == nil {
		t.Error("PEP is nil")
	}

	// Close 호출 검증
	if err := stack.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}
