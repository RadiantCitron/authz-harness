package catalog

import (
	"os"
	"testing"

	"authz-harness/internal/harness"
)

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("/dev/fd unavailable: %v", err)
	}
	return len(ents)
}

// 계획 021 S1 — L5: env.Cleanup 이 setupHarnessStack 이 연 파일 핸들(감사 기록기)을 닫는다.
func TestPlan021_L5_StackClosedByEnvCleanup(t *testing.T) {
	env, err := harness.NewSandboxEnvironment(harness.SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	before := openFDs(t)
	if _, err := setupHarnessStack(env); err != nil {
		t.Fatal(err)
	}
	if openFDs(t) <= before {
		t.Skip("stack holds no extra file descriptor; cannot observe close")
	}
	if err := env.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("file descriptors leaked after env.Cleanup: before=%d after=%d", before, after)
	}
}
