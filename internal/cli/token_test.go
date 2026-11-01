package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

func setupCLITestRig(t *testing.T) (*TokenRunner, *bytes.Buffer, *bytes.Buffer, string, string) {
	t.Helper()
	tmpDir := t.TempDir()

	privPath := filepath.Join(tmpDir, "signing_keys.priv.json")
	pubPath := filepath.Join(tmpDir, "jwks.pub.json")
	replayPath := filepath.Join(tmpDir, "replay_ledger.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	runner, err := NewTokenRunner(out, errOut, privPath, pubPath, replayPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create token runner: %v", err)
	}

	// 초기 키 1개 생성
	keysRunner, err := NewKeysRunner(out, errOut, privPath, pubPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create keys runner: %v", err)
	}
	code := keysRunner.Run(context.Background(), []string{"rotate"})
	if code != domain.ExitSuccess {
		t.Fatalf("failed to initialize key via keys runner: %d", code)
	}
	out.Reset()
	errOut.Reset()

	return runner, out, errOut, privPath, pubPath
}

func TestCLI_TokenIssueAndVerify(t *testing.T) {
	runner, out, errOut, _, _ := setupCLITestRig(t)

	// 1. Issue
	issueArgs := []string{
		"issue",
		"--client-id", "client-orchestrator",
		"--client-secret", "orchestrator-secret-key-01",
		"--sub", "worker-01",
		"--scope", "file:read:docs/plan.txt",
		"--aud", "authz-service",
	}

	exitCode := runner.Run(context.Background(), issueArgs)
	if exitCode != domain.ExitSuccess {
		t.Fatalf("issue expected exit 0, got %d, err: %s", exitCode, errOut.String())
	}

	issueOutput := out.String()
	if !strings.Contains(issueOutput, "PASS: [TOKEN_ISSUED]") {
		t.Fatalf("expected TOKEN_ISSUED in output: %s", issueOutput)
	}

	// Extract token string
	lines := strings.Split(strings.TrimSpace(issueOutput), "\n")
	tokenStr := lines[len(lines)-1]

	out.Reset()
	errOut.Reset()

	// 2. Inspect
	inspectArgs := []string{
		"inspect",
		"--token", tokenStr,
	}
	exitCode = runner.Run(context.Background(), inspectArgs)
	if exitCode != domain.ExitSuccess {
		t.Fatalf("inspect expected exit 0, got %d, err: %s", exitCode, errOut.String())
	}

	var inspectData map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &inspectData); err != nil {
		t.Fatalf("inspect output not valid json: %v", err)
	}

	out.Reset()
	errOut.Reset()

	// 3. Verify
	verifyArgs := []string{
		"verify",
		"--token", tokenStr,
		"--expected-sub", "worker-01",
		"--expected-aud", "authz-service",
		"--record-replay",
	}
	exitCode = runner.Run(context.Background(), verifyArgs)
	if exitCode != domain.ExitSuccess {
		t.Fatalf("verify expected exit 0, got %d, err: %s", exitCode, errOut.String())
	}

	if !strings.Contains(out.String(), "PASS: [GATE_1_VERIFIED]") {
		t.Fatalf("expected GATE_1_VERIFIED, got: %s", out.String())
	}

	out.Reset()
	errOut.Reset()

	// 4. Verify Replay (2회차는 차단되어야 함)
	exitCode = runner.Run(context.Background(), verifyArgs)
	if exitCode != domain.ExitTokenInvalid {
		t.Fatalf("verify replay expected exit 11, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "TOKEN_REPLAY_DETECTED") {
		t.Fatalf("expected TOKEN_REPLAY_DETECTED, got: %s", out.String())
	}
}

func TestCLI_FaultInjection(t *testing.T) {
	runner, out, errOut, _, _ := setupCLITestRig(t)

	// Tampered Signature
	issueArgs := []string{
		"issue",
		"--client-id", "client-orchestrator",
		"--client-secret", "orchestrator-secret-key-01",
		"--sub", "worker-01",
		"--tamper-signature",
	}

	exitCode := runner.Run(context.Background(), issueArgs)
	if exitCode != domain.ExitSuccess {
		t.Fatalf("issue expected exit 0, got %d", exitCode)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	tamperedToken := lines[len(lines)-1]
	out.Reset()
	errOut.Reset()

	verifyArgs := []string{
		"verify",
		"--token", tamperedToken,
	}
	exitCode = runner.Run(context.Background(), verifyArgs)
	if exitCode != domain.ExitTokenInvalid {
		t.Fatalf("expected exit 11 for tampered signature, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "TOKEN_INVALID_SIGNATURE") {
		t.Fatalf("expected TOKEN_INVALID_SIGNATURE, got: %s", out.String())
	}
}
