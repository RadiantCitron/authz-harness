// Package observe 는 코어 인가 계층이 운영 관측(로그·추적)을 내보내는 포트를 정의한다.
// 이 패키지는 log/slog 및 OTel 타입을 노출하지 않으며, 구현체는 하위 어댑터 패키지에 둔다.
// 관측은 best-effort 이며 인가 판정과 감사 기록에 영향을 주지 않는다.
package observe

import (
	"context"

	"authz-harness/internal/domain"
)

// Attr 는 관측 이벤트에 붙는 키-값 속성이다.
type Attr struct {
	Key   string
	Value any
}

// Observer 는 소비자(PEP 등)가 필요로 하는 최소 관측 인터페이스다.
type Observer interface {
	OnStageStart(ctx context.Context, traceID, stage string, attrs ...Attr)
	OnStageEnd(ctx context.Context, traceID, stage string, allowed bool, attrs ...Attr)
	OnExecutionEnd(ctx context.Context, traceID string, allowed bool, attrs ...Attr)
	OnError(ctx context.Context, traceID, msg string, attrs ...Attr)
}

// NoopObserver 는 아무것도 하지 않는 Observer 다.
type NoopObserver struct{}

func (NoopObserver) OnStageStart(context.Context, string, string, ...Attr)     {}
func (NoopObserver) OnStageEnd(context.Context, string, string, bool, ...Attr) {}
func (NoopObserver) OnExecutionEnd(context.Context, string, bool, ...Attr)     {}
func (NoopObserver) OnError(context.Context, string, string, ...Attr)          {}

type safeObserver struct{ inner Observer }

// WrapSafe 는 어댑터의 panic 이 호출자(판정 경로)로 전파되지 않도록 감싼다.
// nil 은 NoopObserver 가 되며, 이미 감싼 것은 다시 감싸지 않는다.
func WrapSafe(o Observer) Observer {
	switch v := o.(type) {
	case nil:
		return NoopObserver{}
	case safeObserver:
		return v
	}
	return safeObserver{inner: o}
}

func (s safeObserver) OnStageStart(ctx context.Context, traceID, stage string, attrs ...Attr) {
	defer func() { _ = recover() }()
	s.inner.OnStageStart(ctx, traceID, stage, attrs...)
}

func (s safeObserver) OnStageEnd(ctx context.Context, traceID, stage string, allowed bool, attrs ...Attr) {
	defer func() { _ = recover() }()
	s.inner.OnStageEnd(ctx, traceID, stage, allowed, attrs...)
}

func (s safeObserver) OnExecutionEnd(ctx context.Context, traceID string, allowed bool, attrs ...Attr) {
	defer func() { _ = recover() }()
	s.inner.OnExecutionEnd(ctx, traceID, allowed, attrs...)
}

func (s safeObserver) OnError(ctx context.Context, traceID, msg string, attrs ...Attr) {
	defer func() { _ = recover() }()
	s.inner.OnError(ctx, traceID, msg, attrs...)
}

// SanitizeAttrs 는 문자열 값과 error 값의 원시 토큰을 치환한 새 슬라이스를 반환한다.
func SanitizeAttrs(attrs []Attr) []Attr {
	out := make([]Attr, len(attrs))
	for i, a := range attrs {
		switch v := a.Value.(type) {
		case string:
			a.Value = domain.RedactRawTokens(v)
		case error:
			a.Value = domain.RedactRawTokens(v.Error())
		}
		out[i] = a
	}
	return out
}
