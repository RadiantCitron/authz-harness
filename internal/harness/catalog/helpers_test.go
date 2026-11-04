package catalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/mcp"
)

// TC-040-06: harnessStack.Close() 호출 시 리소스 정상 해제 검증
func TestTC_040_06_HarnessStack_Close(t *testing.T) {
	tempDir := t.TempDir()
	env, err := harness.NewSandboxEnvironment(harness.SandboxConfig{
		BaseDir: tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}
	defer env.Cleanup()

	stack, err := setupHarnessStack(env)
	if err != nil {
		t.Fatalf("setupHarnessStack failed: %v", err)
	}

	// 감사 이벤트 하나 기록
	_ = stack.AuditWriter.Log(audit.Event{
		Timestamp: time.Now().UTC(),
		TraceID:   "trc-close-test",
		Decision:  "allow",
		Reason:    "AUTHORIZED",
		Success:   true,
	})

	// Close 호출
	if err := stack.Close(); err != nil {
		t.Fatalf("stack.Close returned error: %v", err)
	}

	// Close 후 audit.jsonl 이 다른 프로세스나 테스트에서 재오픈 가능한지 확인
	f, err := os.OpenFile(env.AuditPath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open audit file after stack.Close(): %v", err)
	}
	_ = f.Close()
}

// TC-040-08: 워커 컨테이너(Zone B 전용) 조립 시 Zone A(개인키) 미접근 검증
func TestTC_040_08_ZoneB_NoZoneAAccess(t *testing.T) {
	tempDir := t.TempDir()
	env, err := harness.NewSandboxEnvironment(harness.SandboxConfig{
		BaseDir: tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}
	defer env.Cleanup()

	// 1. 정상적으로 초기 키 발급 및 서명
	stack, err := setupHarnessStack(env)
	if err != nil {
		t.Fatalf("setupHarnessStack failed: %v", err)
	}
	defer stack.Close()

	ctx := context.Background()
	_, err = grantPermission(ctx, stack, "worker-zb", domain.ActionFileRead, "data.txt")
	if err != nil {
		t.Fatalf("grantPermission failed: %v", err)
	}
	_ = os.WriteFile(filepath.Join(env.WorkspaceDir, "data.txt"), []byte("zone b content"), 0644)

	tok, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01", "worker-zb", "file:read", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		t.Fatalf("issueTestToken failed: %v", err)
	}

	// 2. Zone A 개인키 파일 의도적 제거 (Zone B 격리 환경 시뮬레이션)
	_ = os.Remove(env.PrivKeyPath)

	// 3. 공개키(JWKS)만 남은 상태에서 토큰 검증 및 PEP 집행 실행
	claims, err := stack.TokenVerifier.VerifyToken(tok, token.VerifyOptions{
		ExpectedAudience: domain.DefaultAudience,
	}, domain.AuditContext{
		TraceID: "trc-zone-b",
	})
	if err != nil {
		t.Fatalf("VerifyToken failed without private key (public JWKS should suffice): %v", err)
	}
	if claims.Claims.Subject != "worker-zb" {
		t.Fatalf("expected subject worker-zb, got %s", claims.Claims.Subject)
	}
}

// TC-010-05: isError 인데 structuredContent 가 없으면 fail-closed (ExitInternalError).
func TestExitCodeFromResponse_FailClosed(t *testing.T) {
	cases := []struct {
		name string
		resp mcp.JSONRPCResponse
		want domain.ExitCode
		err  bool
	}{
		{"structuredContent 없음", mcp.JSONRPCResponse{Result: map[string]any{"isError": true}}, domain.ExitInternalError, true},
		{"exit_code 비숫자", mcp.JSONRPCResponse{Result: map[string]any{"isError": true, "structuredContent": map[string]any{"exit_code": "12"}}}, domain.ExitInternalError, true},
		{"정상 구조", mcp.JSONRPCResponse{Result: map[string]any{"isError": true, "structuredContent": map[string]any{"exit_code": float64(13)}}}, domain.ExitPathViolation, false},
		{"성공", mcp.JSONRPCResponse{Result: map[string]any{}}, domain.ExitSuccess, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := exitCodeFromResponse(&c.resp)
			if got != c.want || (err != nil) != c.err {
				t.Fatalf("got (%d, %v) want (%d, err=%v)", got, err, c.want, c.err)
			}
		})
	}
}
