// Package orchestrator 는 OS 프로세스 그룹 격리 및 신호 전달 기능을 제공한다.
package orchestrator

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// configureProcessGroup 은 자식 프로세스를 새 독립 프로세스 그룹(Setpgid: true)에 두고,
// 취소 시 그룹 전체(음수 PID)에 SIGKILL 을 발행하여 자식 및 손자 프로세스까지 완벽히 종료하도록 설정한다.
func configureProcessGroup(cmd *exec.Cmd, waitDelay time.Duration) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = waitDelay
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// 음수 PID 에 SIGKILL 을 전송하여 해당 프로세스 그룹 전체를 한 번에 종료한다.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
