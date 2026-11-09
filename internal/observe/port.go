// Package observe 는 코어 인가 계층이 운영 관측(로그·추적)을 내보내는 DIP 포트 규약을 정의한다.
//
// [관측 아키텍처 및 무결성 보호 원칙]
// 1. 코어 패키지 의존성 격리 (No log/slog & No OTel in Core):
//   - 코어 계층(`pep`, `pdp`, `pipeline` 등)은 표준 로거(`log/slog`)나 OTel SDK 를 직접 참조하지 않고 오직 observe.Observer 포트만 호출한다.
//   - 아키텍처 가드레일 TC-140-01 에 의해 코어 패키지의 `log/slog` 직접 import 가 차단된다.
//
// 2. 패닉 격리 (WrapSafe):
//   - 외부 관측 어댑터나 로깅 시스템에서 발생하는 런타임 panic 이 인가 판정 및 감사 기록 등 핵심 보안 경로를 중단시키지 않도록
//     WrapSafe 래퍼가 recover() 로 격리한다 (Fail-Closed 보안 보장).
//
// 3. 베스트 에포트(Best-Effort) 성격:
//   - 관측(Observe)은 디버깅 및 시스템 텔레메트리를 위한 보조 수단이며, 법적 증거인 감사 로그(Audit)와 명확히 분리된다.
//   - 관측 실패는 인가 판정에 영향을 주지 않는다.
//
// 4. Zero Leakage 속성 마스킹 (SanitizeAttrs):
//   - 로그로 흘러가는 문자열 및 error 객체 내부의 원시 토큰 패턴을 domain.RedactRawTokens 로 마스킹하여 로그 파일에 비밀값이 노출되는 것을 방지한다.
package observe

import (
	"context"

	"authz-harness/internal/domain"
)

// Attr 는 관측 이벤트에 부가되는 키-값 속성(Attribute) 구조체다.
type Attr struct {
	Key   string
	Value any
}

// Observer 는 소비자(PEP, Orchestrator 등)가 필요로 하는 최소 관측 DIP 인터페이스다.
type Observer interface {
	// OnStageStart 는 파이프라인 검문소 단계 진입 시 호출된다.
	OnStageStart(ctx context.Context, traceID, stage string, attrs ...Attr)

	// OnStageEnd 는 파이프라인 검문소 단계 통과/차단 완료 시 호출된다.
	OnStageEnd(ctx context.Context, traceID, stage string, allowed bool, attrs ...Attr)

	// OnExecutionEnd 는 전체 도구 또는 요청 실행의 최종 종료 시 호출된다.
	OnExecutionEnd(ctx context.Context, traceID string, allowed bool, attrs ...Attr)

	// OnError 는 런타임 비즈니스 에러 발생 시 호출된다.
	OnError(ctx context.Context, traceID, msg string, attrs ...Attr)
}

// NoopObserver 는 관측이 비활성화되었을 때 아무 동작도 하지 않는 Null Object 패턴 구현체다.
type NoopObserver struct{}

func (NoopObserver) OnStageStart(context.Context, string, string, ...Attr)     {}
func (NoopObserver) OnStageEnd(context.Context, string, string, bool, ...Attr) {}
func (NoopObserver) OnExecutionEnd(context.Context, string, bool, ...Attr)     {}
func (NoopObserver) OnError(context.Context, string, string, ...Attr)          {}

type safeObserver struct{ inner Observer }

// WrapSafe 는 어댑터의 panic 이 호출자(판정 경로)로 전파되지 않도록 안전하게 감싼다.
// nil 은 NoopObserver 가 되며, 이미 감싸진 객체는 중복 감싸지 않는다.
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

// SanitizeAttrs 는 문자열 값과 error 값에 포함된 원시 Bearer 토큰을 [REDACTED] 로 치환한 새 슬라이스를 반환한다.
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
