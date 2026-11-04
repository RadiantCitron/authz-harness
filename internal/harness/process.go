package harness

import (
	"errors"
	"syscall"
	"time"
)

// WaitForProcessGone 은 pid 프로세스가 사라질 때까지 10ms 주기로 확인한다. 시험용 증거 수집 함수다.
func WaitForProcessGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
