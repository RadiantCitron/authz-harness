package harness_test

import (
	"os"
	"testing"

	"authz-harness/internal/harness"
)

func TestCachedBinaryProvider(t *testing.T) {
	provider := harness.NewCachedBinaryProvider()
	defer func() {
		_ = provider.Cleanup()
	}()

	binPath, err := provider.GetBinaryPath()
	if err != nil {
		t.Fatalf("failed to get binary path: %v", err)
	}

	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("failed to stat binary %s: %v", binPath, err)
	}
	if info.Size() == 0 {
		t.Fatalf("binary is empty")
	}

	// 2차 호출 시 동일 경로 반환 검증
	binPath2, err := provider.GetBinaryPath()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if binPath != binPath2 {
		t.Fatalf("expected same binary path, got %s vs %s", binPath, binPath2)
	}
}
