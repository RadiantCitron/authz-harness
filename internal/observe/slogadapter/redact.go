// Package slogadapter 는 log/slog 핸들러 옵션에서 토큰을 마스킹하는 치환기를 제공한다.
package slogadapter

import (
	"log/slog"

	"authz-harness/internal/domain"
)

// RedactReplaceAttr 는 slog.HandlerOptions.ReplaceAttr 용 함수로, 로그 속성(과 메시지)의
// 문자열·error 값에 섞인 원시 토큰을 domain.RedactRawTokens 로 치환한다.
// 운영 로그를 만드는 모든 핸들러에 지정해 호출처마다 마스킹을 반복하지 않게 한다 (Zero Leakage).
func RedactReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(domain.RedactRawTokens(v.String()))
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			a.Value = slog.StringValue(domain.RedactRawTokens(err.Error()))
		}
	}
	return a
}
