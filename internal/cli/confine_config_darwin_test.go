//go:build darwin

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/confinement"
)

// -confine 이 만드는 정책이 실제 커널(Seatbelt)에서 Zone A 직접 읽기를 막는지 확인한다.
// 대조군 두 개를 함께 둔다: ① 격리 없이는 같은 파일이 읽힌다, ② 격리 중에도 workspace 파일은 읽힌다.
// (정책이 너무 좁아 모든 것을 막는 가짜 차단을 배제하기 위함)
func TestConfinePolicyBlocksZoneAOnSeatbelt(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	zoneA := filepath.Join(root, ".authz-state", "private")
	zoneB := filepath.Join(root, ".authz-state", "public")
	ws := filepath.Join(root, "workspace")
	for _, d := range []string{zoneA, zoneB, ws} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const canary = "ZONE-A-CANARY-9f3a"
	privFile := filepath.Join(zoneA, "signing_keys.priv.json")
	wsFile := filepath.Join(ws, "ok.txt")
	audit := filepath.Join(root, "audit.jsonl")
	for path, body := range map[string]string{privFile: canary, wsFile: "workspace-ok", audit: ""} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(zoneB, "grants_state.json")
	pol, err := buildConfinementPolicy(privFile, state, filepath.Join(zoneB, "jwks.pub.json"), filepath.Join(zoneB, "replay_ledger.json"), ws, audit, "")
	if err != nil {
		t.Fatal(err)
	}
	confiner := confinement.Platform()

	// 대조군 ①: 격리 없이는 읽힌다
	out, err := exec.Command("/bin/cat", privFile).CombinedOutput()
	if err != nil || !strings.Contains(string(out), canary) {
		t.Fatalf("대조군 실패: 격리 없이 Zone A 를 읽지 못했다 (err=%v out=%q)", err, out)
	}

	// 대조군 ②: 격리 중에도 workspace 는 읽힌다
	okCmd := exec.Command("/bin/cat", wsFile)
	if err := confiner.Prepare(okCmd, pol); err != nil {
		t.Skipf("이 환경에서는 격리를 적용할 수 없다: %v", err)
	}
	out, err = okCmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "workspace-ok") {
		t.Fatalf("정책이 너무 좁다: 격리 중 workspace 를 읽지 못했다 (err=%v out=%q)", err, out)
	}

	// 실험군: 격리 중 Zone A 직접 읽기는 커널이 막는다
	blockedCmd := exec.Command("/bin/cat", privFile)
	if err := confiner.Prepare(blockedCmd, pol); err != nil {
		t.Fatal(err)
	}
	out, err = blockedCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("격리 중인데 Zone A 가 읽혔다: %q", out)
	}
	if strings.Contains(string(out), canary) {
		t.Fatalf("Zone A 내용이 유출되었다: %q", out)
	}
}
