package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

func setupCLITestRig(t *testing.T) (*TokenRunner, *bytes.Buffer, *bytes.Buffer, string, string) {
	t.Helper()
	tmpDir := t.TempDir()

	statePath := filepath.Join(tmpDir, "grants_state.json")
	privPath := filepath.Join(tmpDir, "signing_keys.priv.json")
	pubPath := filepath.Join(tmpDir, "jwks.pub.json")
	replayPath := filepath.Join(tmpDir, "replay_ledger.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	runner, err := NewTokenRunner(out, errOut, statePath, privPath, pubPath, replayPath, auditPath)
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

	if !strings.Contains(out.String(), "PASS: [TOKEN_VERIFIED]") {
		t.Fatalf("expected TOKEN_VERIFIED, got: %s", out.String())
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

func TestTokenRunner_Exchange_LineageEpochEnforced(t *testing.T) {
	runner, out, errOut, privPath, _ := setupCLITestRig(t)
	tmpDir := filepath.Dir(privPath)
	statePath := filepath.Join(tmpDir, "grants_state.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	// 1. 부모 토큰 발급 (orchestrator-main: Epoch 1)
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

	// 2. 부모 주체(orchestrator-main)의 Security Epoch 증가 (상위 주체 권한 회수)
	grantRunner, err := NewGrantRunner(out, errOut, statePath, auditPath)
	if err != nil {
		t.Fatalf("failed to create grant runner: %v", err)
	}
	bumpCode := grantRunner.Run(context.Background(), []string{"bump-epoch", "-sub", "orchestrator-main"})
	if bumpCode != domain.ExitSuccess {
		t.Fatalf("bump-epoch failed: %d, err: %s", bumpCode, errOut.String())
	}
	out.Reset()
	errOut.Reset()

	// 3. 폐기된 부모 토큰으로 새 토큰 교환 시도 -> lineage_epoch 단계에서 차단되어야 함
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
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected exchange failure with exit code %d (ExitAuthzDenied), got %d, out: %s, err: %s",
			domain.ExitAuthzDenied, exitCode, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "SUBJECT_EPOCH_REVOKED") {
		t.Fatalf("expected SUBJECT_EPOCH_REVOKED in exchange output, got: %s", out.String())
	}

	// 4. 감사 로그에서 StageLineageEpoch 단계 및 SUBJECT_EPOCH_REVOKED 거부 확인
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}
	var foundLineageEpochDeny bool
	for _, l := range strings.Split(string(auditBytes), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var ev struct {
			Action string `json:"action"`
			Stage  string `json:"stage"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal([]byte(l), &ev) == nil {
			if ev.Action == "token.exchange.deny" && ev.Stage == string(domain.StageLineageEpoch) && ev.Reason == string(domain.ReasonSubjectEpochRevoked) {
				foundLineageEpochDeny = true
				break
			}
		}
	}
	if !foundLineageEpochDeny {
		t.Fatalf("expected audit event with stage=lineage_epoch and reason=SUBJECT_EPOCH_REVOKED, not found in audit.jsonl:\n%s", string(auditBytes))
	}
}

func TestTokenRunner_NegativeClockOffset_Rejected(t *testing.T) {
	runner, out, errOut, _, _ := setupCLITestRig(t)

	// 1. 정상 토큰 발급
	issueArgs := []string{
		"issue",
		"--client-id", "client-orchestrator",
		"--client-secret", "orchestrator-secret-key-01",
		"--sub", "orchestrator-main",
		"--scope", "file:read:docs/plan.txt",
		"--aud", "authz-service",
		"--ttl", "1h",
	}
	if code := runner.Run(context.Background(), issueArgs); code != domain.ExitSuccess {
		t.Fatalf("issue failed: %d, err: %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	tok := lines[len(lines)-1]
	out.Reset()
	errOut.Reset()

	// 2. token verify --clock-offset -10m (음수 오프셋 거부) -> ExitBadInput (14)
	verifyArgs := []string{
		"verify",
		"--token", tok,
		"--clock-offset", "-10m",
	}
	if code := runner.Run(context.Background(), verifyArgs); code != domain.ExitBadInput {
		t.Fatalf("expected verify with negative offset to return ExitBadInput(14), got %d, out: %s, err: %s",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "must not be negative") {
		t.Fatalf("expected 'must not be negative' in stderr, got: %s", errOut.String())
	}
	out.Reset()
	errOut.Reset()

	// 3. token exchange --clock-offset -10m (음수 오프셋 거부) -> ExitBadInput (14)
	exchangeArgs := []string{
		"exchange",
		"--client-id", "client-subagent",
		"--client-secret", "subagent-secret-key-02",
		"--parent-token", tok,
		"--child-sub", "worker-01",
		"--scope", "file:read:docs/plan.txt",
		"--ttl", "30m",
		"--clock-offset", "-10m",
	}
	if code := runner.Run(context.Background(), exchangeArgs); code != domain.ExitBadInput {
		t.Fatalf("expected exchange with negative offset to return ExitBadInput(14), got %d, out: %s, err: %s",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "must not be negative") {
		t.Fatalf("expected 'must not be negative' in stderr, got: %s", errOut.String())
	}
}

// TestTokenRunner_ReusedRunner_ClockOffset_Honored 는 동일한 TokenRunner 인스턴스로
// issue 후 exchange --clock-offset +2h 호출 시, 기존 스택 캐싱 버그(AP4-01) 없이
// 주입된 가상 시계(OffsetClock)가 정상 적용되어 만료된 부모 토큰이 거부(ExitTokenInvalid 12)됨을 검증한다.
func TestTokenRunner_ReusedRunner_ClockOffset_Honored(t *testing.T) {
	runner, out, errOut, _, _ := setupCLITestRig(t)

	// 1. 1시간 TTL 부모 토큰 발급 (RealClock 기준)
	issueArgs := []string{
		"issue",
		"--client-id", "client-orchestrator",
		"--client-secret", "orchestrator-secret-key-01",
		"--sub", "orchestrator-main",
		"--scope", "file:read:docs/plan.txt",
		"--aud", "authz-service",
		"--ttl", "1h",
	}
	if code := runner.Run(context.Background(), issueArgs); code != domain.ExitSuccess {
		t.Fatalf("issue failed: %d, err: %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	parentTok := lines[len(lines)-1]
	out.Reset()
	errOut.Reset()

	// 2. 동일 runner 인스턴스로 exchange --clock-offset +2h 실행
	// 부모 토큰은 1시간 후 만료이므로, +2시간 시계에서는 반드시 만료(TOKEN_EXPIRED) 거부되어야 함.
	exchangeArgs := []string{
		"exchange",
		"--client-id", "client-subagent",
		"--client-secret", "subagent-secret-key-02",
		"--parent-token", parentTok,
		"--child-sub", "worker-01",
		"--scope", "file:read:docs/plan.txt",
		"--ttl", "30m",
		"--clock-offset", "+2h",
	}
	code := runner.Run(context.Background(), exchangeArgs)
	if code != domain.ExitTokenInvalid {
		t.Fatalf("expected exchange with +2h offset on 1h token to return ExitTokenInvalid(12), got %d, out: %s, err: %s",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "TOKEN_EXPIRED") {
		t.Fatalf("expected 'TOKEN_EXPIRED' in stdout, got: %s", out.String())
	}
}

// TestTokenRunner_Verify_NoZoneAPrivateKeyRequired 는 검증자 환경에서
// Zone A 개인키(privPath)가 아예 존재하지 않아도 token verify 가 정상 동작하며,
// 불필요하게 Zone A 개인키 파일이 디스크에 생성되지 않음을 검증한다 (VerifyOnly 격리).
func TestTokenRunner_Verify_NoZoneAPrivateKeyRequired(t *testing.T) {
	tmpDir := t.TempDir()

	statePath := filepath.Join(tmpDir, "grants_state.json")
	privPath := filepath.Join(tmpDir, "signing_keys.priv.json") // 생성하지 않음!
	pubPath := filepath.Join(tmpDir, "jwks.pub.json")
	replayPath := filepath.Join(tmpDir, "replay_ledger.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	// 정상 토큰 1개와 pubPath(JWKS)만 별도 발급 장치에서 준비
	issuerDir := t.TempDir()
	issuerPriv := filepath.Join(issuerDir, "signing_keys.priv.json")
	issuerPub := pubPath // 공개키는 공유
	issuerRunner, err := NewTokenRunner(&bytes.Buffer{}, &bytes.Buffer{}, statePath, issuerPriv, issuerPub, replayPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create issuer runner: %v", err)
	}
	var issueOut, issueErr bytes.Buffer
	issuerRunner.out = &issueOut
	issuerRunner.errOut = &issueErr
	code := issuerRunner.Run(context.Background(), []string{
		"issue",
		"--client-id", "client-orchestrator",
		"--client-secret", "orchestrator-secret-key-01",
		"--sub", "worker-01",
		"--scope", "file:read:docs/plan.txt",
		"--aud", "authz-service",
	})
	if code != domain.ExitSuccess {
		t.Fatalf("failed to issue token: %d, err: %s", code, issueErr.String())
	}
	lines := strings.Split(strings.TrimSpace(issueOut.String()), "\n")
	tok := lines[len(lines)-1]

	// 이제 privPath 가 존재하지 않는 검증자 러너 생성
	var verifyOut, verifyErr bytes.Buffer
	verifierRunner, err := NewTokenRunner(&verifyOut, &verifyErr, statePath, privPath, pubPath, replayPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create verifier runner: %v", err)
	}

	// verify 실행
	vCode := verifierRunner.Run(context.Background(), []string{"verify", "--token", tok})
	if vCode != domain.ExitSuccess {
		t.Fatalf("expected verify to succeed without private key, got %d, out: %s, err: %s",
			vCode, verifyOut.String(), verifyErr.String())
	}

	// Zone A 비밀키 파일이 검증 과정에서 생성되지 않았는지 확인 (Zero Leakage / VerifyOnly)
	if _, err := os.Stat(privPath); !os.IsNotExist(err) {
		t.Fatalf("expected privPath to NOT exist in verify-only mode, but file was created: %v", err)
	}
}
