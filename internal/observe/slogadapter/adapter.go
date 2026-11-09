// Package slogadapter 는 observe.Observer 를 표준 라이브러리 log/slog 로 구현하는 기본 운영 로그 어댑터다.
//
// [운영 로그 삼분 및 보안 원칙]
// - CLI 출력(stdout), 감사 증거(audit.jsonl)와 명확히 분리되어 stderr 로 나가는 개발/운영 디버깅 로그를 담당한다.
// - RedactReplaceAttr 핸들러 및 observe.SanitizeAttrs 를 통해 원시 토큰 유출을 원천 차단한다.
package slogadapter

import (
	"context"
	"log/slog"

	"authz-harness/internal/observe"
)

type adapter struct{ l *slog.Logger }

// New 는 log/slog 기반 Observer 인스턴스를 생성한다. l 이 nil 이면 slog.Default() 를 사용한다.
func New(l *slog.Logger) observe.Observer {
	if l == nil {
		l = slog.Default()
	}
	return adapter{l: l}
}

// args 는 trace_id 와 정제된 속성들을 slog 의 키-값 슬라이스 형태로 변환한다.
func args(traceID string, attrs []observe.Attr) []any {
	attrs = observe.SanitizeAttrs(attrs)
	out := make([]any, 0, 2+2*len(attrs))
	out = append(out, "trace_id", traceID)
	for _, a := range attrs {
		out = append(out, a.Key, a.Value)
	}
	return out
}

// OnStageStart 는 PEP 단계 진입을 Debug 레벨 로그로 출력한다.
func (a adapter) OnStageStart(ctx context.Context, traceID, stage string, attrs ...observe.Attr) {
	a.l.DebugContext(ctx, "pep stage entering", args(traceID, append([]observe.Attr{{Key: "stage", Value: stage}}, attrs...))...)
}

// OnStageEnd 는 PEP 단계 통과(Info) 또는 차단(Warn) 완료를 로그로 출력한다.
func (a adapter) OnStageEnd(ctx context.Context, traceID, stage string, allowed bool, attrs ...observe.Attr) {
	all := append([]observe.Attr{{Key: "stage", Value: stage}}, attrs...)
	if allowed {
		a.l.InfoContext(ctx, "pep stage passed", args(traceID, all)...)
		return
	}
	a.l.WarnContext(ctx, "pep stage blocked", args(traceID, all)...)
}

// OnExecutionEnd 는 전체 실행 성공(Info) 또는 거부/실패(Warn) 완료를 로그로 출력한다.
func (a adapter) OnExecutionEnd(ctx context.Context, traceID string, allowed bool, attrs ...observe.Attr) {
	if allowed {
		a.l.InfoContext(ctx, "pep execution succeeded", args(traceID, attrs)...)
		return
	}
	a.l.WarnContext(ctx, "pep execution denied or failed", args(traceID, attrs)...)
}

// OnError 는 실행 중 발생한 런타임 오류를 Error 레벨 로그로 출력한다.
func (a adapter) OnError(ctx context.Context, traceID, msg string, attrs ...observe.Attr) {
	a.l.ErrorContext(ctx, msg, args(traceID, attrs)...)
}
