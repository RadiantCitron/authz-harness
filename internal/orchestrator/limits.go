package orchestrator

import (
	"fmt"
	"time"

	"authz-harness/internal/domain"
)

const (
	// DefaultSpawnTimeout 은 자식 프로세스 기본 제한 시간이다.
	DefaultSpawnTimeout = 10 * time.Second
	// DefaultWaitDelay 는 그룹 종료 후 입출력 파이프 정리를 기다리는 기본 시간이다.
	DefaultWaitDelay = 500 * time.Millisecond
	// DefaultMaxOutputBytes 는 stdout·stderr 각각의 기본 출력 상한이다.
	DefaultMaxOutputBytes int64 = 1 << 20
)

// Limits 는 부모 스포너가 자식에게 강제하는 자원·수명 한계다.
// MaxOutputBytes 는 stdout 과 stderr 에 각각 적용된다.
type Limits struct {
	Timeout        time.Duration
	WaitDelay      time.Duration
	MaxOutputBytes int64
}

// DefaultLimits 는 기본 한계 값을 반환한다.
func DefaultLimits() Limits {
	return Limits{
		Timeout:        DefaultSpawnTimeout,
		WaitDelay:      DefaultWaitDelay,
		MaxOutputBytes: DefaultMaxOutputBytes,
	}
}

// Normalize 는 음수 필드를 거부하고 영값 필드를 기본값으로 채운 사본을 반환한다.
func (l Limits) Normalize() (Limits, error) {
	if l.Timeout < 0 || l.WaitDelay < 0 || l.MaxOutputBytes < 0 {
		return Limits{}, domain.NewError(domain.ReasonInvalidArguments, "orchestrator_limits",
			fmt.Sprintf("negative limit: timeout=%v wait_delay=%v max_output_bytes=%d", l.Timeout, l.WaitDelay, l.MaxOutputBytes), nil)
	}
	d := DefaultLimits()
	if l.Timeout == 0 {
		l.Timeout = d.Timeout
	}
	if l.WaitDelay == 0 {
		l.WaitDelay = d.WaitDelay
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = d.MaxOutputBytes
	}
	return l, nil
}
