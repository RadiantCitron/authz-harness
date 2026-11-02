package domain

import (
	"context"
	"sync"
	"time"
)

// DomainEvent 는 비즈니스 관문에서 발생한 순수 도메인 사건을 표현한다.
type DomainEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	TraceID   string                 `json:"trace_id"`
	Stage     string                 `json:"stage"`
	Actor     string                 `json:"actor"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Decision  string                 `json:"decision"`
	Reason    Reason                 `json:"reason"`
	TokenJTI  string                 `json:"token_jti,omitempty"`
	Success   bool                   `json:"success"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// EventRecorder 는 도메인 이벤트를 수집/기록하는 인터페이스다 (DIP 적용).
type EventRecorder interface {
	Record(event DomainEvent)
}

// EventBuffer 는 인메모리 슬라이스에 도메인 이벤트를 저장하는 순수 메모리 구현체다.
type EventBuffer struct {
	mu     sync.RWMutex
	events []DomainEvent
}

// NewEventBuffer 는 빈 EventBuffer 를 초기화한다.
func NewEventBuffer() *EventBuffer {
	return &EventBuffer{
		events: make([]DomainEvent, 0),
	}
}

// Record 는 이벤트를 스레드 안전하게 버퍼에 추가한다.
func (b *EventBuffer) Record(event DomainEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
}

// Events 는 현재까지 수집된 도메인 이벤트 사본을 반환한다.
func (b *EventBuffer) Events() []DomainEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]DomainEvent, len(b.events))
	copy(copied, b.events)
	return copied
}

// Clear 는 버퍼를 비운다.
func (b *EventBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = b.events[:0]
}

// Context 키 타입
type eventRecorderKey struct{}

// WithEventRecorder 는 context 에 EventRecorder 를 주입한다.
func WithEventRecorder(ctx context.Context, recorder EventRecorder) context.Context {
	return context.WithValue(ctx, eventRecorderKey{}, recorder)
}

// EventRecorderFromContext 는 context 로부터 EventRecorder 를 꺼내며, 없으면 nil 을 반환한다.
func EventRecorderFromContext(ctx context.Context) EventRecorder {
	if ctx == nil {
		return nil
	}
	val := ctx.Value(eventRecorderKey{})
	if r, ok := val.(EventRecorder); ok {
		return r
	}
	return nil
}
