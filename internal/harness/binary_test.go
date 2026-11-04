package harness_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

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

func buildFaultWorker(t *testing.T) string {
	t.Helper()
	p := harness.NewFaultWorkerProvider()
	t.Cleanup(func() { _ = p.Cleanup() })
	path, err := p.GetBinaryPath()
	if err != nil {
		t.Fatalf("fault worker build: %v", err)
	}
	return path
}

// TC-040-01
func TestFaultWorker_BogusModeExits2(t *testing.T) {
	err := exec.Command(buildFaultWorker(t), "-mode", "bogus").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("want exit 2, got %v", err)
	}
}

// TC-040-02
func TestFaultWorker_SpawnChildHang(t *testing.T) {
	cmd := exec.Command(buildFaultWorker(t), "-mode", "spawn_child_hang")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("read first line: %v", err)
	}
	var pid int
	if _, err := fmt.Sscanf(line, "CHILD_PID=%d", &pid); err != nil || pid <= 0 {
		t.Fatalf("bad first line %q", line)
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Wait()
	if !harness.WaitForProcessGone(pid, time.Second) {
		t.Fatalf("grandchild %d still alive", pid)
	}
}

// TC-040-03
func TestFaultWorker_FloodKeepsWriting(t *testing.T) {
	cmd := exec.Command(buildFaultWorker(t), "-mode", "flood")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	n, err := io.ReadFull(out, make([]byte, 64*1024))
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if err != nil || n != 64*1024 {
		t.Fatalf("read %d bytes: %v", n, err)
	}
}
