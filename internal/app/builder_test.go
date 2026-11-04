package app_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/app"
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

// TC-030-04: 활성 키가 폐기된 뒤에도 토큰 발급 스택은 자동 회전하고, keys 부분 경로 스택은 회전하지 않는다.
func TestBuildStack_RotationOnlyForIssuingStack(t *testing.T) {
	tmpDir := t.TempDir()
	base := app.AppConfig{
		PrivKeyPath: filepath.Join(tmpDir, "priv.json"),
		PubJWKSPath: filepath.Join(tmpDir, "pub.json"),
		AuditPath:   filepath.Join(tmpDir, "audit.jsonl"),
	}

	keysStack, err := app.BuildStack(base) // keys CLI 형태 (ReplayPath 없음)
	if err != nil {
		t.Fatalf("keys stack: %v", err)
	}
	active, err := keysStack.KeyManager.GetActiveSigningKey()
	if err != nil || active == nil {
		t.Fatalf("bootstrap active key missing: %v", err)
	}
	if err := keysStack.KeyManager.RevokeKey(active.KID, domain.AuditContext{TraceID: "t", Actor: "test", Reason: "test"}); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	keysStack.Close()

	again, err := app.BuildStack(base)
	if err != nil {
		t.Fatalf("keys stack again: %v", err)
	}
	if k, _ := again.KeyManager.GetActiveSigningKey(); k != nil {
		t.Error("keys-only stack must not auto-rotate a new active key")
	}
	again.Close()

	issuing := base
	issuing.ReplayPath = filepath.Join(tmpDir, "replay.json")
	stack, err := app.BuildStack(issuing)
	if err != nil {
		t.Fatalf("issuing stack: %v", err)
	}
	defer stack.Close()
	if k, err := stack.KeyManager.GetActiveSigningKey(); err != nil || k == nil {
		t.Errorf("issuing stack must rotate to a new active key: %v", err)
	}
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
