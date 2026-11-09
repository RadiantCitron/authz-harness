// Package domain 은 원시 Bearer 토큰(JWT) 유출 방지(Zero Leakage)를 위한 정규식 검출 및 마스킹 기능을 제공한다.
//
// [Zero Leakage 보안 원칙]
// 1. 원시 토큰의 영구 장부 기록 금지:
//    - 서명된 Bearer 토큰(eyJ...) 전체가 감사 로그(audit.jsonl)나 운영 디버그 로그(stderr)에 그대로 출력되면
//      로그 열람자나 공격자에게 토큰 탈취 및 재사용 공격 기회를 제공하게 된다.
// 2. 단일 검출 규칙 공유:
//    - rawTokenPattern 은 감사 해시 체인 직렬화기와 slogadapter 의 RedactReplaceAttr 필터가 공통으로 사용하여
//      시스템 전역에서 동일한 기준으로 토큰을 마스킹한다.
package domain

import "regexp"

// RedactedToken 은 원시 JWT 토큰이 마스킹 치환된 자리에 남는 표준 식별 표식이다.
const RedactedToken = "[REDACTED_TOKEN]"

// rawTokenPattern 은 서명된 Bearer 토큰(JWT eyJ...) 유출 여부를 검출하는 단일 정규표현식 규칙이다.
// Base64URL 로 인코딩된 헤더("eyJ...")로 시작하는 10자 이상의 문자열 패턴을 포착한다.
var rawTokenPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_\.\-]{10,}`)

// ContainsRawToken 은 주어진 문자열 s 에 원시 JWT 로 보이는 패턴이 포함되어 있는지 판정한다.
// 감사 로거가 디스크에 기록하기 전 유출 여부를 정적 검사할 때 사용된다.
func ContainsRawToken(s string) bool {
	return rawTokenPattern.MatchString(s)
}

// RedactRawTokens 는 문자열 s 안에서 원시 JWT 패턴과 일치하는 모든 구간을 RedactedToken 으로 안전하게 치환한다.
// slog 운영 로그 어댑터 및 CLI 오류 출력 포매터에서 사용된다.
func RedactRawTokens(s string) string {
	return rawTokenPattern.ReplaceAllString(s, RedactedToken)
}
