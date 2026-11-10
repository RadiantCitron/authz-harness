package app_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
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

// T-03: VerifyOnly 모드 검증 (Zone A 미접근, 서명키 자동 회전 없음, Issuer/PAP nil 허용)
func TestBuildStack_VerifyOnlyMode(t *testing.T) {
	tmpDir := t.TempDir()
	pubPath := filepath.Join(tmpDir, "keys_pub.json")
	privPath := filepath.Join(tmpDir, "should_not_exist_priv.json")

	// 먼저 pubJWKS 파일만 준비
	if err := os.WriteFile(pubPath, []byte(`{"version":1,"keys":[]}`), 0644); err != nil {
		t.Fatalf("failed to prep pub jwks: %v", err)
	}

	cfg := app.AppConfig{
		StatePath:    filepath.Join(tmpDir, "state.json"),
		PrivKeyPath:  privPath,
		PubJWKSPath:  pubPath,
		ReplayPath:   filepath.Join(tmpDir, "replay.json"),
		AuditPath:    filepath.Join(tmpDir, "audit.jsonl"),
		WorkspaceDir: filepath.Join(tmpDir, "workspace"),
		VerifyOnly:   true,
		Clock:        mockClock{now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)},
	}

	stack, err := app.BuildStack(cfg)
	if err != nil {
		t.Fatalf("BuildStack(VerifyOnly) failed: %v", err)
	}
	defer stack.Close()

	// Zone A 파일이 생성되지 않았음을 확인
	if _, err := os.Stat(privPath); !os.IsNotExist(err) {
		t.Errorf("Zone A private file should NOT be touched in VerifyOnly mode: %s", privPath)
	}

	// VerifyOnly 모드에서는 Issuer 및 PAP가 nil이어야 함
	if stack.TokenIssuer != nil {
		t.Error("TokenIssuer should be nil in VerifyOnly mode")
	}
	if stack.PAP != nil {
		t.Error("PAP should be nil in VerifyOnly mode")
	}

	// 검증기 및 PEP는 정상이어야 함
	if stack.TokenVerifier == nil {
		t.Error("TokenVerifier should not be nil")
	}
	if stack.PEP == nil {
		t.Error("PEP should not be nil")
	}
}

// TC-030-09: BudgetPath 가 비면 ReplayPath 디렉터리 기준으로 파생되고, 같은 원장을 공유한다.
func TestBuildStack_BudgetPathDerivedFromReplayPath(t *testing.T) {
	d := t.TempDir()
	cfg := app.AppConfig{
		StatePath:    filepath.Join(d, "state.json"),
		PrivKeyPath:  filepath.Join(d, "keys_priv.json"),
		PubJWKSPath:  filepath.Join(d, "keys_pub.json"),
		ReplayPath:   filepath.Join(d, "sub", "replay_ledger.json"),
		AuditPath:    filepath.Join(d, "audit.jsonl"),
		WorkspaceDir: filepath.Join(d, "ws"),
		Clock:        mockClock{now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)},
	}
	stack, err := app.BuildStack(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if stack.BudgetLedger == nil || stack.ExchangeService == nil {
		t.Fatal("BudgetLedger/ExchangeService must be wired")
	}
	if got, want := stack.Config.BudgetPath, filepath.Join(d, "sub", "budget_ledger.json"); got != want {
		t.Fatalf("BudgetPath=%s want %s", got, want)
	}
	if err := stack.BudgetLedger.Init("j1", domain.Budget{MaxCalls: 2}, 1<<40); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stack.Config.BudgetPath); err != nil {
		t.Fatalf("ledger file not created at derived path: %v", err)
	}

	cfg.VerifyOnly = true
	vo, err := app.BuildStack(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer vo.Close()
	if vo.ExchangeService != nil {
		t.Error("VerifyOnly must not build ExchangeService")
	}
	if _, ok, _ := vo.BudgetLedger.Get("j1"); !ok {
		t.Error("VerifyOnly stack must see the shared ledger")
	}
}

// TC-030-03: 상태·감사 경로만 준 부분 경로 조립은 불필요한 원장·키 파일을 만들지 않는다.
func TestBuildStack_PartialPaths_NoStrayFiles(t *testing.T) {
	tmpDir := t.TempDir()
	stack, err := app.BuildStack(app.AppConfig{
		StatePath: filepath.Join(tmpDir, "state.json"),
		AuditPath: filepath.Join(tmpDir, "audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("BuildStack failed: %v", err)
	}
	defer stack.Close()

	if stack.PAP == nil || stack.PDP == nil {
		t.Error("PAP/PDP must be assembled for state-only config")
	}
	if stack.PEP != nil || stack.KeyManager != nil || stack.TokenVerifier != nil {
		t.Error("PEP/KeyManager/TokenVerifier must not be assembled without key paths")
	}
	for _, name := range []string{"budget_ledger.json", "replay_ledger.json"} {
		if _, err := os.Stat(filepath.Join(tmpDir, name)); err == nil {
			t.Errorf("unexpected file created: %s", name)
		}
	}
	if _, err := os.Stat("budget_ledger.json"); err == nil {
		t.Error("budget_ledger.json must not be created in the working directory")
	}
}

// TC-030-04 (계획 052 M1~M3, ADR 0011 D-3): 활성 키를 폐기한 뒤에는 발급 스택도 새 키를 자동으로 만들지 않는다.
// 발급은 거부되고, 관리자가 명시적으로 회전해야 재개된다.
func TestBuildStack_NoAutoRotationAfterActiveKeyRevoked(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := app.AppConfig{
		PrivKeyPath:    filepath.Join(tmpDir, "priv.json"),
		PubJWKSPath:    filepath.Join(tmpDir, "pub.json"),
		ReplayPath:     filepath.Join(tmpDir, "replay.json"),
		AuditPath:      filepath.Join(tmpDir, "audit.jsonl"),
		WithoutGateway: true,
	}

	first, err := app.BuildStack(cfg)
	if err != nil {
		t.Fatalf("first stack: %v", err)
	}
	active, err := first.KeyManager.GetActiveSigningKey()
	if err != nil || active == nil {
		t.Fatalf("bootstrap active key missing: %v", err)
	}
	revokedKID := active.KID
	if err := first.KeyManager.RevokeKey(revokedKID, domain.AuditContext{TraceID: "t", Actor: "test", Reason: "test"}); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	first.Close()

	// M1: 다시 조립해도 활성 키가 생기지 않고, key.rotated 기록도 없다.
	stack, err := app.BuildStack(cfg)
	if err != nil {
		t.Fatalf("M1: issuing stack must still assemble: %v", err)
	}
	defer stack.Close()
	if k, _ := stack.KeyManager.GetActiveSigningKey(); k != nil {
		t.Fatalf("M1: issuing stack must not auto-create an active key, got %s", k.KID)
	}
	if n := countAuditAction(t, cfg.AuditPath, "key.rotated"); n != 0 {
		t.Fatalf("M1: key.rotated count = %d, want 0", n)
	}

	// M2: 발급은 거부되고(16) 토큰은 나오지 않으며 token.issue.deny 가 남는다.
	req := token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Scope: "file:read:a.txt", TTL: time.Minute, Epoch: 1,
	}
	res, err := stack.TokenIssuer.IssueToken(req, token.IssueOptions{}, domain.AuditContext{TraceID: "m2", Actor: "test"})
	if err == nil {
		t.Fatal("M2: issue must fail without an active key")
	}
	if res != nil && res.TokenString != "" {
		t.Fatal("M2: no token string may be returned")
	}
	if code := domain.ExitCodeFromError(err, domain.ExitTokenInvalid); code != domain.ExitInternalError {
		t.Errorf("M2: exit code = %d, want %d", code, domain.ExitInternalError)
	}
	if n := countAuditAction(t, cfg.AuditPath, "token.issue.deny"); n != 1 {
		t.Errorf("M2: token.issue.deny count = %d, want 1", n)
	}

	// M3: 명시적 회전 후에는 새 키로 발급된다.
	if _, err := stack.KeyManager.RotateKey(domain.AuditContext{TraceID: "m3", Actor: "test", Reason: "resume"}); err != nil {
		t.Fatalf("M3: RotateKey: %v", err)
	}
	res, err = stack.TokenIssuer.IssueToken(req, token.IssueOptions{}, domain.AuditContext{TraceID: "m3", Actor: "test"})
	if err != nil {
		t.Fatalf("M3: issue after rotate: %v", err)
	}
	if res.KeyID == "" || res.KeyID == revokedKID {
		t.Errorf("M3: kid = %q, want a new kid different from %q", res.KeyID, revokedKID)
	}
}

// 계획 052 M4: 키가 하나도 없는 첫 설치에서는 최초 키 생성이 그대로 되고 발급이 성공한다 (회귀 방지).
func TestBuildStack_BootstrapKeyStillCreatedOnFirstRun(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := app.AppConfig{
		PrivKeyPath:    filepath.Join(tmpDir, "priv.json"),
		PubJWKSPath:    filepath.Join(tmpDir, "pub.json"),
		ReplayPath:     filepath.Join(tmpDir, "replay.json"),
		AuditPath:      filepath.Join(tmpDir, "audit.jsonl"),
		WithoutGateway: true,
	}
	stack, err := app.BuildStack(cfg)
	if err != nil {
		t.Fatalf("stack: %v", err)
	}
	defer stack.Close()
	if n := countAuditAction(t, cfg.AuditPath, "key.created"); n != 1 {
		t.Errorf("key.created count = %d, want 1", n)
	}
	if _, err := stack.TokenIssuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Scope: "file:read:a.txt", TTL: time.Minute, Epoch: 1,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "m4", Actor: "test"}); err != nil {
		t.Fatalf("issue on first run: %v", err)
	}
}

// countAuditAction 은 감사 파일에서 action 이 일치하는 줄 수를 센다.
func countAuditAction(t *testing.T, path, action string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("parse audit line: %v", err)
		}
		if ev.Action == action {
			n++
		}
	}
	return n
}

// TC-030-05: PDP·검증기가 있는데 워크스페이스가 없으면 조용히 건너뛰지 않고 거부한다(Fail-Closed).
func TestBuildStack_MissingWorkspace_FailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	stack, err := app.BuildStack(app.AppConfig{
		StatePath:   filepath.Join(tmpDir, "state.json"),
		PrivKeyPath: filepath.Join(tmpDir, "priv.json"),
		PubJWKSPath: filepath.Join(tmpDir, "pub.json"),
		ReplayPath:  filepath.Join(tmpDir, "replay.json"),
		AuditPath:   filepath.Join(tmpDir, "audit.jsonl"),
	})
	// 에러 문구 매칭은 AP-10 가드가 금지하므로 거부 사실(에러 + nil 스택)만 단언한다.
	if err == nil || stack != nil {
		t.Fatalf("expected BuildStack to reject missing workspace, got stack=%v err=%v", stack, err)
	}
}

// TC-030-06: VerifyOnly 이면서 게이트웨이를 조립할 재료가 없으면 PEP 는 nil 로 남는다.
func TestBuildStack_VerifyOnlyWithoutGateway_StaysNil(t *testing.T) {
	tmpDir := t.TempDir()
	stack, err := app.BuildStack(app.AppConfig{
		StatePath:  filepath.Join(tmpDir, "state.json"),
		AuditPath:  filepath.Join(tmpDir, "audit.jsonl"),
		VerifyOnly: true,
	})
	if err != nil {
		t.Fatalf("BuildStack failed: %v", err)
	}
	defer stack.Close()
	if stack.PEP != nil {
		t.Error("stack.PEP must be nil when no gateway is assembled")
	}
}
