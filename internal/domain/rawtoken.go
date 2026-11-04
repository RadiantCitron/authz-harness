package domain

import "regexp"

// RedactedToken 은 원시 토큰이 치환된 자리에 남는 표식이다.
const RedactedToken = "[REDACTED_TOKEN]"

// rawTokenPattern 은 서명된 Bearer 토큰(JWT eyJ...) 유출 여부를 검출하는 단일 규칙이다.
// 감사 해시 체인 검증과 관측성 속성 필터가 이 규칙을 공유한다.
var rawTokenPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_\.\-]{10,}`)

// ContainsRawToken 은 s 에 원시 JWT 로 보이는 문자열이 있는지 판정한다.
func ContainsRawToken(s string) bool {
	return rawTokenPattern.MatchString(s)
}

// RedactRawTokens 는 s 안의 원시 JWT 로 보이는 구간을 RedactedToken 으로 치환한다.
func RedactRawTokens(s string) string {
	return rawTokenPattern.ReplaceAllString(s, RedactedToken)
}
