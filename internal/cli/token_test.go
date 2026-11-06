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

func TestCLI_TokenExchange(t *testing.T) {
	runner, out, errOut, _, _ := setupCLITestRig(t)

	// 1. 부모 토큰 발급 (orchestrator: scope 2개)
	issueArgs := []string{
		"issue",
		"--client-id", "client-orchestrator",
		"--client-secret", "orchestrator-secret-key-01",
		"--sub", "orchestrator-main",
		"--scope", "file:read:docs/plan.txt file:write:docs/out.txt",
		"--aud", "authz-service",
		"--ttl", "1h",
	}
	exitCode := runner.Run(context.Background(), issueArgs)
	if exitCode != domain.ExitSuccess {
		t.Fatalf("parent issue failed: %d, err: %s", exitCode, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	parentToken := lines[len(lines)-1]
	out.Reset()
	errOut.Reset()

	// 2. 정상 Token Exchange 축소 위임 (worker-01: scope 1개, 30분)
	exchangeArgs := []string{
		"exchange",
		"--client-id", "client-subagent",
		"--client-secret", "subagent-secret-key-02",
		"--parent-token", parentToken,
		"--child-sub", "worker-01",
		"--scope", "file:read:docs/plan.txt",
		"--ttl", "30m",
	}
	exitCode = runner.Run(context.Background(), exchangeArgs)
	if exitCode != domain.ExitSuccess {
		t.Fatalf("exchange expected exit 0, got %d, err: %s", exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "RFC 8693 Token Exchange & Downscoping Pipeline [SUCCESS]") {
		t.Fatalf("expected success banner, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "Delegation:    Depth 1 (Parent -> worker-01)") {
		t.Fatalf("expected Depth 1 in output: %s", out.String())
	}

	// 자식 토큰 파싱
	exchangeOutLines := strings.Split(strings.TrimSpace(out.String()), "\n")
	childToken := exchangeOutLines[len(exchangeOutLines)-2]
	childToken = strings.TrimPrefix(childToken, "│ ")
	out.Reset()
	errOut.Reset()

	// 3. 자식 토큰 inspect 확인 (act claim 포함 여부)
	inspectArgs := []string{
		"inspect",
		"--token", childToken,
	}
	exitCode = runner.Run(context.Background(), inspectArgs)
	if exitCode != domain.ExitSuccess {
		t.Fatalf("inspect child token failed: %d, err: %s", exitCode, errOut.String())
	}
	var inspectData map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &inspectData); err != nil {
		t.Fatalf("inspect output not valid json: %v", err)
	}
	claimsMap := inspectData["claims"].(map[string]interface{})
	if claimsMap["sub"] != "worker-01" {
		t.Errorf("expected sub worker-01, got %v", claimsMap["sub"])
	}
	actMap, ok := claimsMap["act"].(map[string]interface{})
	if !ok || actMap["sub"] != "orchestrator-main" {
		t.Errorf("expected act.sub orchestrator-main, got %v", actMap)
	}
	out.Reset()
	errOut.Reset()

	// 4. 초과 권한 위임 거부 테스트 (DELEGATION_SCOPE_EXCEEDED)
	exceedArgs := []string{
		"exchange",
		"--client-id", "client-subagent",
		"--client-secret", "subagent-secret-key-02",
		"--parent-token", parentToken,
		"--child-sub", "worker-01",
		"--scope", "file:read:docs/plan.txt file:write:docs/unauthorized.txt",
		"--ttl", "30m",
	}
	exitCode = runner.Run(context.Background(), exceedArgs)
	// 계획 017 D-03·D-05: 교환 거부는 사유별 종료 코드를 따른다(축소 위임 위반은 12).
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected exit 12 for scope exceeded, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "DELEGATION_SCOPE_EXCEEDED") {
		t.Fatalf("expected DELEGATION_SCOPE_EXCEEDED in output, got: %s", out.String())
	}
}
