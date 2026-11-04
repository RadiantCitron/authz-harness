package orchestrator

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// configureProcessGroup 은 자식을 새 프로세스 그룹에 두고, 취소 시 그룹 전체를 SIGKILL 하도록 설정한다.
func configureProcessGroup(cmd *exec.Cmd, waitDelay time.Duration) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = waitDelay
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
