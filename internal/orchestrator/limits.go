// Package orchestrator 는 서브에이전트 자식 프로세스의 자원 및 수명 제한을 정의한다.
package orchestrator

import (
	"fmt"
	"time"

	"authz-harness/internal/domain"
)

const (
	// DefaultSpawnTimeout 은 자식 프로세스 기본 제한 시간이다 (10초).
	DefaultSpawnTimeout = 10 * time.Second

	// DefaultWaitDelay 는 그룹 종료 후 입출력 파이프 정리를 기다리는 기본 시간이다 (500ms).
	DefaultWaitDelay = 500 * time.Millisecond

	// DefaultMaxOutputBytes 는 stdout·stderr 각각의 기본 출력 상한이다 (1MB).
	DefaultMaxOutputBytes int64 = 1 << 20
)

// Limits 는 부모 스포너가 자식 프로세스에게 강제하는 자원·수명 한계다.
// MaxOutputBytes 는 stdout 과 stderr 에 각각 독립적으로 적용된다.
type Limits struct {
	// Timeout 은 프로세스 최대 실행 시간이다. 초과 시 SIGKILL 이 발행된다.
	Timeout time.Duration

	// WaitDelay 는 SIGKILL 전송 후 파이프 닫힘을 기다리는 완충 시간이다.
	WaitDelay time.Duration

	// MaxOutputBytes 는 stdout 및 stderr 각각의 최대 바이트 상한이다.
	MaxOutputBytes int64
}

// DefaultLimits 는 시스템 표준 기본 한계 값을 반환한다.
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
		return Limits{}, domain.NewError(domain.ReasonInvalidArguments,
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
