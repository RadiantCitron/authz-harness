package harness

import (
	"os"
	"strings"
	"testing"
)

// 계획 021 S1 — T6: ReadAuditEvents 가 100KB 기록을 오류 없이 읽는다.
func TestReadAuditEvents_T6_Large100KB(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer env.Cleanup()
	line := `{"trace_id":"t","step":"s","resource":"` + strings.Repeat("r", 100*1024) + `"}` + "\n"
	if err := os.WriteFile(env.AuditPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	evs, err := env.ReadAuditEvents()
	if err != nil || len(evs) != 1 {
		t.Fatalf("evs=%d err=%v", len(evs), err)
	}
}
