package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/domain"
)

func countOpenFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("/dev/fd unavailable: %v", err)
	}
	return len(ents)
}

// 계획 032 S4: R1 - Runner 5종 각각 Run 전후 열린 FD 수가 동일해야 한다 (누수 0건).
func TestRunnerFDLeak_R1(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	privPath := filepath.Join(dir, "keys.priv.json")
	pubPath := filepath.Join(dir, "jwks.pub.json")
	replayPath := filepath.Join(dir, "replay.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	wsDir := filepath.Join(dir, "workspace")
	_ = os.MkdirAll(wsDir, 0o755)

	var out, errOut bytes.Buffer

	// KeysRunner
	keysR, err := NewKeysRunner(&out, &errOut, privPath, pubPath, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	before := countOpenFDs(t)
	keysR.Run(context.Background(), []string{"rotate"})
	if after := countOpenFDs(t); after != before {
		t.Fatalf("KeysRunner FD leak: before=%d after=%d", before, after)
	}

	// GrantRunner
	grantR, err := NewGrantRunner(&out, &errOut, statePath, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	before = countOpenFDs(t)
	grantR.Run(context.Background(), []string{"create", "--sub", "w1", "--action", "file:read", "--resource", "a.txt"})
	if after := countOpenFDs(t); after != before {
		t.Fatalf("GrantRunner FD leak: before=%d after=%d", before, after)
	}

	// ApprovalRunner
	apprR, err := NewApprovalRunner(&out, &errOut, statePath, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	before = countOpenFDs(t)
	apprR.Run(context.Background(), []string{"list"})
	if after := countOpenFDs(t); after != before {
		t.Fatalf("ApprovalRunner FD leak: before=%d after=%d", before, after)
	}

	// PDPRunner
	pdpR, err := NewPDPRunner(&out, &errOut, statePath, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	before = countOpenFDs(t)
	pdpR.Run(context.Background(), []string{"decide", "--sub", "w1", "--action", "file:read", "--resource", "a.txt", "--scope", "file:read:a.txt"})
	if after := countOpenFDs(t); after != before {
		t.Fatalf("PDPRunner FD leak: before=%d after=%d", before, after)
	}

	// PEPRunner (미존재 토큰 거부 경로)
	pepR, err := NewPEPRunner(&out, &errOut, wsDir, statePath, pubPath, replayPath, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	before = countOpenFDs(t)
	pepR.Run(context.Background(), []string{"read", "-token", "bad.jwt", "a.txt"})
	if after := countOpenFDs(t); after != before {
		t.Fatalf("PEPRunner FD leak: before=%d after=%d", before, after)
	}
}

// 계획 032 S4: R2 - 감사 파일 경로가 디렉터리인 경우 초기화 실패 시 16 반환 및 stderr 메시지 확인.
func TestRunnerInitFailure_R2(t *testing.T) {
	dir := t.TempDir()
	badAuditPath := dir // 디렉터리 경로를 전달하면 파일 생성 실패

	var out, errOut bytes.Buffer
	ctx := context.Background()

	// GrantRunner
	grantR, _ := NewGrantRunner(&out, &errOut, filepath.Join(dir, "state.json"), badAuditPath)
	errOut.Reset()
	if code := grantR.Run(ctx, []string{"list"}); code != domain.ExitInternalError || !bytes.Contains(errOut.Bytes(), []byte("failed to initialize grant runner")) {
		t.Errorf("GrantRunner R2 failed: code=%d stderr=%s", code, errOut.String())
	}

	// ApprovalRunner
	apprR, _ := NewApprovalRunner(&out, &errOut, filepath.Join(dir, "state.json"), badAuditPath)
	errOut.Reset()
	if code := apprR.Run(ctx, []string{"list"}); code != domain.ExitInternalError || !bytes.Contains(errOut.Bytes(), []byte("failed to initialize approval runner")) {
		t.Errorf("ApprovalRunner R2 failed: code=%d stderr=%s", code, errOut.String())
	}

	// PDPRunner
	pdpR, _ := NewPDPRunner(&out, &errOut, filepath.Join(dir, "state.json"), badAuditPath)
	errOut.Reset()
	if code := pdpR.Run(ctx, []string{"decide"}); code != domain.ExitInternalError || !bytes.Contains(errOut.Bytes(), []byte("failed to initialize pdp runner")) {
		t.Errorf("PDPRunner R2 failed: code=%d stderr=%s", code, errOut.String())
	}

	// KeysRunner
	keysR, _ := NewKeysRunner(&out, &errOut, filepath.Join(dir, "p.json"), filepath.Join(dir, "pub.json"), badAuditPath)
	errOut.Reset()
	if code := keysR.Run(ctx, []string{"list"}); code != domain.ExitInternalError || !bytes.Contains(errOut.Bytes(), []byte("failed to initialize keys runner")) {
		t.Errorf("KeysRunner R2 failed: code=%d stderr=%s", code, errOut.String())
	}

	// PEPRunner
	pepR, _ := NewPEPRunner(&out, &errOut, dir, filepath.Join(dir, "state.json"), filepath.Join(dir, "pub.json"), filepath.Join(dir, "replay.json"), badAuditPath)
	errOut.Reset()
	if code := pepR.Run(ctx, []string{"read"}); code != domain.ExitInternalError || !bytes.Contains(errOut.Bytes(), []byte("failed to initialize pep runner")) {
		t.Errorf("PEPRunner R2 failed: code=%d stderr=%s", code, errOut.String())
	}
}
