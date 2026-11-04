//go:build darwin

package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/confinement"
)

// TC-040-07: 실제 Seatbelt 하에서 정직한 헬퍼가 workspace 에 쓰기.
func TestSpawnerConfinementDarwinReal(t *testing.T) {
	c := confinement.Platform()
	if !c.Available() {
		t.Skip("seatbelt unavailable: nested sandbox")
	}
	real, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(real, "sb")
	ws, zb := filepath.Join(root, "workspace"), filepath.Join(root, "zone_b")
	audit := filepath.Join(root, "audit.jsonl")
	for _, d := range []string{ws, zb} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(ws, "out.txt")
	pol := confinement.WorkerPolicy(root, ws, zb, audit)
	s := confSpawner(t, "write_marker", &recWriter{}, []string{"MARKER_FILE=" + marker}, c, pol)
	res, err := s.Spawn(context.Background(), confReq("tr-real"))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	if b, _ := os.ReadFile(marker); string(b) != "ok" {
		t.Fatal("marker not written under confinement")
	}
}
