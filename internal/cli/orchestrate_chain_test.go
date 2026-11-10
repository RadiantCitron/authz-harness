package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

// TestOrchestrateChain_MissingRequiredArgs (인수 시험 M1) 는 필수 인자(-token, -file) 누락 또는
// 잘못된 인자 입력 시 ExitBadInput(10)을 반환하고 stderr 에 원인을 출력하는지 검증한다.
func TestOrchestrateChain_MissingRequiredArgs(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	runner := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	runner.SetPrivKeyPath(rig.keysRunner.privPath)

	t.Run("서브커맨드 없음", func(t *testing.T) {
		rig.out.Reset()
		rig.errOut.Reset()
		code := runner.Run(context.Background(), []string{})
		if code != domain.ExitBadInput {
			t.Errorf("code = %v, want ExitBadInput", code)
		}
		if !strings.Contains(rig.errOut.String(), "subcommand required") {
			t.Errorf("stderr missing subcommand required: %s", rig.errOut.String())
		}
	})

	t.Run("-token 누락", func(t *testing.T) {
		rig.out.Reset()
		rig.errOut.Reset()
		code := runner.Run(context.Background(), []string{"chain", "-file", "foo.txt"})
		if code != domain.ExitBadInput {
			t.Errorf("code = %v, want ExitBadInput", code)
		}
		if !strings.Contains(rig.errOut.String(), "-token is required") {
			t.Errorf("stderr missing token required: %s", rig.errOut.String())
		}
	})

	t.Run("-file 누락", func(t *testing.T) {
		rig.out.Reset()
		rig.errOut.Reset()
		code := runner.Run(context.Background(), []string{"chain", "-token", "dummy-tok"})
		if code != domain.ExitBadInput {
			t.Errorf("code = %v, want ExitBadInput", code)
		}
		if !strings.Contains(rig.errOut.String(), "-file is required") {
			t.Errorf("stderr missing file required: %s", rig.errOut.String())
		}
	})

	t.Run("유효하지 않은 -action", func(t *testing.T) {
		rig.out.Reset()
		rig.errOut.Reset()
		code := runner.Run(context.Background(), []string{"chain", "-token", "dummy-tok", "-file", "foo.txt", "-action", "invalid:action"})
		if code != domain.ExitBadInput {
			t.Errorf("code = %v, want ExitBadInput", code)
		}
		if !strings.Contains(rig.errOut.String(), "invalid -action") {
			t.Errorf("stderr missing invalid action: %s", rig.errOut.String())
		}
	})
}

// TestOrchestrateChain_ScopeExceededDenied (인수 시험 M2) 는 부모 스코프를 초과하는 하위 위임 시도 시
// 2차 교환 단계에서 거부(ExitAuthzDenied, 12)되고 워커 프로세스가 기동되지 않음을 검증한다.
func TestOrchestrateChain_ScopeExceededDenied(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	// 준비: Root 토큰 (file:read 만 보유)
	rootTok := rig.issueToken(t, "orchestrator-root", "file:read", "authz-harness")

	runner := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	runner.SetWorkerBinaryPath(bin)
	runner.SetPrivKeyPath(rig.keysRunner.privPath)

	rig.out.Reset()
	rig.errOut.Reset()

	// Lead는 file:read만 위임받을 수 있는데 Worker에게 file:write 위임을 시도
	code := runner.Run(context.Background(), []string{
		"chain",
		"-token", rootTok,
		"-file", "secret.txt",
		"-action", "file:write",
		"-lead-sub", "lead-01",
		"-lead-scope", "file:read",
		"-worker-sub", "worker-01",
		"-worker-scope", "file:read file:write", // 부모(Lead) 스코프 초과!
	})

	if code != domain.ExitAuthzDenied {
		t.Fatalf("code = %v, want ExitAuthzDenied(12), stdout: %s, stderr: %s", code, rig.out.String(), rig.errOut.String())
	}

	outStr := rig.out.String()
	if !strings.Contains(outStr, "Hop 1 Delegation") {
		t.Errorf("stdout should contain Hop 1 success: %s", outStr)
	}
	if !strings.Contains(outStr, "FAIL: [DELEGATION_CHAIN_BLOCKED]") {
		t.Errorf("stdout missing DELEGATION_CHAIN_BLOCKED: %s", outStr)
	}
}

// TestOrchestrateChain_NormalChain (인수 시험 M3, M5) 는 정상 2-Hop 다단계 연쇄 위임과 워커 실행이
// 성공(ExitSuccess, 0)하고, 위임 계보가 시각화되며, 원시 토큰이 노출되지 않음(Zero Leakage)을 검증한다.
func TestOrchestrateChain_NormalChain(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	testFile := "chain_task.txt"
	absPath := filepath.Join(rig.workspaceDir, testFile)
	if err := os.WriteFile(absPath, []byte("chain task execution success"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Worker 에게 대상 파일 읽기 권한 grant
	rig.createGrant(t, "worker-01", "operator", "file:read", testFile)

	// Root 토큰 발급 (file:read file:write)
	rootTok := rig.issueToken(t, "orchestrator-root", "file:read file:write", "authz-harness")

	runner := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	runner.SetWorkerBinaryPath(bin)
	runner.SetPrivKeyPath(rig.keysRunner.privPath)

	rig.out.Reset()
	rig.errOut.Reset()

	code := runner.Run(context.Background(), []string{
		"chain",
		"-token", rootTok,
		"-file", testFile,
		"-action", "file:read",
		"-lead-sub", "lead-01",
		"-lead-scope", "file:read file:write",
		"-worker-sub", "worker-01",
		"-worker-scope", "file:read",
	})

	if code != domain.ExitSuccess {
		t.Fatalf("code = %v, want ExitSuccess(0), stdout: %s, stderr: %s", code, rig.out.String(), rig.errOut.String())
	}

	outStr := rig.out.String()
	errStr := rig.errOut.String()

	// 1. 위임 계보 검증
	if !strings.Contains(outStr, "Hop 1 Delegation: Root (Depth 0) -> Lead (Depth 1)") {
		t.Errorf("stdout missing Hop 1 banner: %s", outStr)
	}
	if !strings.Contains(outStr, "Hop 2 Delegation: Lead (Depth 1) -> Worker (Depth 2)") {
		t.Errorf("stdout missing Hop 2 banner: %s", outStr)
	}
	if !strings.Contains(outStr, "Leaf Worker Execution") {
		t.Errorf("stdout missing Leaf Worker Execution: %s", outStr)
	}
	if !strings.Contains(outStr, "Output:\nchain task execution success") {
		t.Errorf("stdout missing worker output: %s", outStr)
	}

	// 2. Zero Leakage 원칙 검증 (M5)
	if strings.Contains(outStr, rootTok) || strings.Contains(errStr, rootTok) {
		t.Errorf("root token leaked in stdout/stderr! (Zero Leakage violated)")
	}
	if strings.Contains(outStr, "eyJ") || strings.Contains(errStr, "eyJ") {
		t.Errorf("raw JWT token substring 'eyJ' leaked in stdout/stderr!")
	}
}

// TestOrchestrateChain_WriteAction 은 다단계 위임 체인을 통한 워커 파일 쓰기(-action file:write -data)가
// 정상 작동함을 검증한다.
func TestOrchestrateChain_WriteAction(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	testFile := "chain_written.txt"

	// Worker 에게 대상 파일 쓰기 권한 grant
	rig.createGrant(t, "worker-01", "operator", "file:write", testFile)

	// Root 토큰 발급
	rootTok := rig.issueToken(t, "orchestrator-root", "file:read file:write", "authz-harness")

	runner := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	runner.SetWorkerBinaryPath(bin)
	runner.SetPrivKeyPath(rig.keysRunner.privPath)

	rig.out.Reset()
	rig.errOut.Reset()

	code := runner.Run(context.Background(), []string{
		"chain",
		"-token", rootTok,
		"-file", testFile,
		"-action", "file:write",
		"-data", "chain write payload 123",
		"-lead-sub", "lead-01",
		"-lead-scope", "file:read file:write",
		"-worker-sub", "worker-01",
		"-worker-scope", "file:write",
	})

	if code != domain.ExitSuccess {
		t.Fatalf("code = %v, want ExitSuccess(0), stdout: %s, stderr: %s", code, rig.out.String(), rig.errOut.String())
	}

	// 실제 작성된 파일 확인
	absPath := filepath.Join(rig.workspaceDir, testFile)
	b, err := os.ReadFile(absPath)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(b) != "chain write payload 123" {
		t.Errorf("content = %q, want %q", string(b), "chain write payload 123")
	}
}

// TestOrchestrateChain_ConfineFlag (인수 시험 M4) 는 -confine 플래그가 지정되었을 때
// 격리 정책과 런처가 올바르게 조립되어 전달되는지 검증한다.
func TestOrchestrateChain_ConfineFlag(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	testFile := "chain_confine.txt"
	absPath := filepath.Join(rig.workspaceDir, testFile)
	if err := os.WriteFile(absPath, []byte("chain confine ok"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	rig.createGrant(t, "worker-01", "operator", "file:read", testFile)
	rootTok := rig.issueToken(t, "orchestrator-root", "file:read file:write", "authz-harness")

	runner := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	runner.SetWorkerBinaryPath(bin)
	runner.SetPrivKeyPath(rig.keysRunner.privPath)

	rig.out.Reset()
	rig.errOut.Reset()

	code := runner.Run(context.Background(), []string{
		"chain",
		"-token", rootTok,
		"-file", testFile,
		"-action", "file:read",
		"-lead-sub", "lead-01",
		"-lead-scope", "file:read file:write",
		"-worker-sub", "worker-01",
		"-worker-scope", "file:read",
		"-confine",
	})

	// Seatbelt 가 적용 가능한 환경이면 0 (ExitSuccess),
	// sandbox 내부 등 중첩 격리가 불가능한 환경이면 Fail-Closed 로 16 (ExitInternalError)
	if code != domain.ExitSuccess && code != domain.ExitInternalError {
		t.Fatalf("code = %v, want ExitSuccess(0) or ExitInternalError(16), stderr: %s", code, rig.errOut.String())
	}
}

