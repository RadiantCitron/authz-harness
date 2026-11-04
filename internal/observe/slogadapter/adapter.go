// Package slogadapter 는 observe.Observer 를 log/slog 로 구현하는 기본 어댑터다.
package slogadapter

import (
	"context"
	"log/slog"

	"authz-harness/internal/observe"
)

type adapter struct{ l *slog.Logger }

// New 는 slog 기반 Observer 를 만든다. l 이 nil 이면 slog.Default() 를 쓴다.
func New(l *slog.Logger) observe.Observer {
	if l == nil {
		l = slog.Default()
	}
	return adapter{l: l}
}

func args(traceID string, attrs []observe.Attr) []any {
	attrs = observe.SanitizeAttrs(attrs)
	out := make([]any, 0, 2+2*len(attrs))
	out = append(out, "trace_id", traceID)
	for _, a := range attrs {
		out = append(out, a.Key, a.Value)
	}
	return out
}

func (a adapter) OnStageStart(ctx context.Context, traceID, stage string, attrs ...observe.Attr) {
	a.l.DebugContext(ctx, "pep stage entering", args(traceID, append([]observe.Attr{{Key: "stage", Value: stage}}, attrs...))...)
}

func (a adapter) OnStageEnd(ctx context.Context, traceID, stage string, allowed bool, attrs ...observe.Attr) {
	all := append([]observe.Attr{{Key: "stage", Value: stage}}, attrs...)
	if allowed {
		a.l.InfoContext(ctx, "pep stage passed", args(traceID, all)...)
		return
	}
	a.l.WarnContext(ctx, "pep stage blocked", args(traceID, all)...)
}

func (a adapter) OnExecutionEnd(ctx context.Context, traceID string, allowed bool, attrs ...observe.Attr) {
	if allowed {
		a.l.InfoContext(ctx, "pep execution succeeded", args(traceID, attrs)...)
		return
	}
	a.l.WarnContext(ctx, "pep execution denied or failed", args(traceID, attrs)...)
}

func (a adapter) OnError(ctx context.Context, traceID, msg string, attrs ...observe.Attr) {
	a.l.ErrorContext(ctx, msg, args(traceID, attrs)...)
}
