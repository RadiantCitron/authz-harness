package app_test

import (
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/app"
)

func buildKeyStack(t *testing.T, priv string, verifyOnly bool) {
	t.Helper()
	buildKeyStackIn(t, t.TempDir(), priv, verifyOnly)
}

func buildKeyStackIn(t *testing.T, root, priv string, verifyOnly bool) {
	t.Helper()
	stack, err := app.BuildStack(app.AppConfig{
		StatePath:      filepath.Join(root, "public", "grants_state.json"),
		PrivKeyPath:    priv,
		PubJWKSPath:    filepath.Join(root, "public", "jwks.pub.json"),
		AuditPath:      filepath.Join(root, "audit.jsonl"),
		WithoutGateway: true,
		VerifyOnly:     verifyOnly,
	})
	if err != nil {
		t.Fatalf("BuildStack: %v", err)
	}
	if err := stack.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return info.Mode().Perm()
}

// Zone A 폴더를 새로 만들면 0700 이고 그 안의 비밀키 파일은 0600 이다.
func TestBuildStack_NewZoneADirIs0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	priv := filepath.Join(dir, "signing_keys.priv.json")
	buildKeyStack(t, priv, false)

	if got := modeOf(t, dir); got != 0700 {
		t.Fatalf("zone A dir mode = %o, want 700", got)
	}
	if got := modeOf(t, priv); got != 0600 {
		t.Fatalf("private key file mode = %o, want 600", got)
	}
}

// 이미 0755 로 만들어진 Zone A 폴더는 다음 조립 때 0700 으로 좁혀진다.
func TestBuildStack_ExistingLooseZoneADirIsTightened(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	buildKeyStack(t, filepath.Join(dir, "signing_keys.priv.json"), false)

	if got := modeOf(t, dir); got != 0700 {
		t.Fatalf("zone A dir mode = %o, want 700", got)
	}
}

// 검증 전용 스택은 Zone A 를 건드리지 않는다: 없는 폴더를 만들지 않고 있는 폴더의 권한도 바꾸지 않는다.
func TestBuildStack_VerifyOnlyDoesNotTouchZoneADir(t *testing.T) {
	root := t.TempDir()
	// 검증 전용 스택은 이미 공개된 키가 있어야 조립되므로 발급 스택으로 먼저 키를 만든다.
	buildKeyStackIn(t, root, filepath.Join(root, "seed", "signing_keys.priv.json"), false)

	missing := filepath.Join(root, "missing")
	buildKeyStackIn(t, root, filepath.Join(missing, "signing_keys.priv.json"), true)
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("verify-only stack created zone A dir: err=%v", err)
	}

	loose := filepath.Join(root, "loose")
	if err := os.Mkdir(loose, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0755); err != nil {
		t.Fatal(err)
	}
	buildKeyStackIn(t, root, filepath.Join(loose, "signing_keys.priv.json"), true)
	if got := modeOf(t, loose); got != 0755 {
		t.Fatalf("verify-only stack changed zone A dir mode to %o", got)
	}
}

// 비밀키 경로에 폴더가 없으면 현재 작업 폴더의 권한을 바꾸지 않는다.
func TestBuildStack_BareKeyFilenameKeepsWorkingDirMode(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Chmod(cwd, 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	buildKeyStack(t, "signing_keys.priv.json", false)

	if got := modeOf(t, cwd); got != 0755 {
		t.Fatalf("working dir mode changed to %o", got)
	}
}
