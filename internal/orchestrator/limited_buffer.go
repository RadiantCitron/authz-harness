// Package orchestrator 는 출력 스트림의 바이트 상한을 강제하는 스레드 안전한 버퍼를 제공한다.
package orchestrator

import (
	"bytes"
	"errors"
	"sync"
)

var errOutputLimitExceeded = errors.New("output limit exceeded")

// limitedBuffer 는 바이트 상한(max)이 있는 동시성 안전 쓰기 버퍼다.
// 상한 초과 시 onExceed 콜백을 sync.Once 로 정확히 한 번 호출하여 부모가 자식 프로세스 그룹을 즉시 종료하도록 유도한다.
type limitedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	max      int64
	exceeded bool
	once     sync.Once
	onExceed func()
}

func newLimitedBuffer(max int64, onExceed func()) *limitedBuffer {
	return &limitedBuffer{max: max, onExceed: onExceed}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	remaining := b.max - int64(b.buf.Len())
	if int64(len(p)) <= remaining && !b.exceeded {
		n, _ := b.buf.Write(p)
		b.mu.Unlock()
		return n, nil
	}
	n := 0
	if remaining > 0 && !b.exceeded {
		n, _ = b.buf.Write(p[:remaining])
	}
	b.exceeded = true
	b.mu.Unlock()
	if b.onExceed != nil {
		b.once.Do(b.onExceed)
	}
	return n, errOutputLimitExceeded
}

func (b *limitedBuffer) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *limitedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}
