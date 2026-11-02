package pep_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// TC-040-02: 데코레이터 미작동 시 정상 통과 (InjectRevokeBeforeIO: false)
func TestTC_040_02_DecoratorNoInterference(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)
	sub := "worker-dec-01"
	resPath := "normal.txt"

	tok := issueValidToken(t, h, sub, "file:read", 10*time.Minute, 1)
	createGrant(t, h, sub, domain.ActionFileRead, resPath)
	_ = os.WriteFile(filepath.Join(h.workspaceDir, resPath), []byte("content"), 0644)

	hookCalled := false
	decorated := pep.WithBeforeIOHook(h.gateway, func(ctx context.Context, req pep.Request) error {
		hookCalled = true
		return nil
	})

	req := pep.Request{
		Token:                tok,
		Action:               domain.ActionFileRead,
		Resource:             resPath,
		InjectRevokeBeforeIO: false,
	}

	result, err := decorated.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	if hookCalled {
		t.Fatal("expected hook NOT to be called when InjectRevokeBeforeIO is false")
	}
	if !result.Allowed || result.ExitCode != domain.ExitSuccess {
		t.Fatalf("expected allowed ExitSuccess(0), got exitCode %d, reason %s", result.ExitCode, result.Reason)
	}
}

// TC-040-03: 데코레이터 작동 시 TOCTOU 차단 (InjectRevokeBeforeIO: true)
func TestTC_040_03_DecoratorTOCTOURevoke(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)
	sub := "worker-toctou-01"
	resPath := "toctou.txt"

	tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)
	createGrant(t, h, sub, domain.ActionFileWrite, resPath)

	stateStore, err := state.NewFileStore(filepath.Join(t.TempDir(), "grants_state.json"))
	if err != nil {
		t.Fatalf("failed to create state store: %v", err)
	}

	hookExecuted := false
	decorated := pep.WithBeforeIOHook(h.gateway, func(ctx context.Context, req pep.Request) error {
		hookExecuted = true
		// PDP 질의 전 Grant 회수 시뮬레이션
		_, err := h.papSvc.RevokeGrant(ctx, "any-or-all")
		// 또는 papSvc를 통해 해당 주체의 Epoch를 올리거나 Grant를 회수
		_ = err
		// 직접 모든 Grant 상태를 REVOKED로 변경
		_ = stateStore
		// h.papSvc 의 상태를 무효화
		_, _ = h.papSvc.BumpEpoch(ctx, sub)
		return nil
	})

	req := pep.Request{
		Token:                tok,
		Action:               domain.ActionFileWrite,
		Resource:             resPath,
		Data:                 []byte("unsafe data"),
		InjectRevokeBeforeIO: true,
	}

	result, err := decorated.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	if !hookExecuted {
		t.Fatal("expected hook to be executed when InjectRevokeBeforeIO is true")
	}
	if result.Allowed {
		t.Fatal("expected request to be denied after TOCTOU hook, but got allowed")
	}
	if result.ExitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied (12), got %d", result.ExitCode)
	}
}

// TC-040-05: 감사 실패 데코레이터/스위치 (InjectAuditFailure) 검증
func TestTC_040_05_InjectAuditFailure(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)
	sub := "worker-audit-fail"
	resPath := "audit_fail.txt"

	tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)
	createGrant(t, h, sub, domain.ActionFileWrite, resPath)

	req := pep.Request{
		Token:              tok,
		Action:             domain.ActionFileWrite,
		Resource:           resPath,
		Data:               []byte("should not be written"),
		InjectAuditFailure: true,
	}

	result, err := h.gateway.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	if result.Allowed {
		t.Fatal("expected denied on injected audit failure")
	}
	if result.ExitCode != domain.ExitAuditFailure {
		t.Fatalf("expected ExitAuditFailure (15), got %d", result.ExitCode)
	}

	// 디스크 변경 0건 검증
	targetPath := filepath.Join(h.workspaceDir, resPath)
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("expected target file not to exist on audit failure, but found it")
	}
}
