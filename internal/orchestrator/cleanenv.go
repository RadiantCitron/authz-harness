// Package orchestrator 는 자식 프로세스 환경변수 격리 및 안전한 정제 기능을 제공한다.
//
// [환경변수 보안 원칙: 화이트리스트 및 차단 접두사 (Zero Leakage)]
// 1. 최소 환경 상속 (Strict Whitelist):
//   - 부모 프로세스의 모든 환경변수를 상속하지 않고, PATH, TMPDIR, HOME 등 필수 시스템 환경변수만 선별적으로 상속한다.
//
// 2. 민감 비밀값 차단 (Blocked Prefixes):
//   - "ZONE_A_", "SECRET_", "AUTHZ_KEY_" 로 시작하는 민감 키 및 서명키 관련 환경변수는 자식 프로세스에 절대 상속되지 않는다.
package orchestrator

import "strings"

// AllowedEnvKeys 는 서브에이전트 자식 프로세스에 상속이 허용된 환경변수 화이트리스트 키 목록이다.
var AllowedEnvKeys = []string{
	"PATH",
	"TMPDIR",
	"TEMP",
	"TMP",
	"HOME",
	"USER",
	"LANG",
	"LC_ALL",
}

// BlockedEnvPrefixes 는 자식 프로세스 상속이 엄격히 차단되는 민감 환경변수 접두사 목록이다.
var BlockedEnvPrefixes = []string{
	"ZONE_A_",
	"SECRET_",
	"AUTHZ_KEY_",
}

// SanitizeEnv 는 입력 환경변수 목록에서 화이트리스트에 부합하고 차단 접두사를 갖지 않는 환경변수만 추출한다.
// 추가 환경변수(extraEnv)가 주어지면 동일한 차단 규칙을 통과한 것에 한해 추가한다.
func SanitizeEnv(environ []string, extraEnv ...string) []string {
	allowedMap := make(map[string]bool, len(AllowedEnvKeys))
	for _, k := range AllowedEnvKeys {
		allowedMap[k] = true
	}

	isSafe := func(entry string) (string, bool) {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 0 || parts[0] == "" {
			return "", false
		}
		key := parts[0]

		// 차단 접두사 검사
		for _, prefix := range BlockedEnvPrefixes {
			if strings.HasPrefix(key, prefix) {
				return "", false
			}
		}

		return key, true
	}

	var sanitized []string
	seen := make(map[string]bool)

	// 기본 환경변수 정제 (화이트리스트에 속하고 차단 접두사가 아닌 것만)
	for _, env := range environ {
		key, ok := isSafe(env)
		if !ok {
			continue
		}
		if allowedMap[key] && !seen[key] {
			sanitized = append(sanitized, env)
			seen[key] = true
		}
	}

	// extraEnv 정제 및 추가
	for _, env := range extraEnv {
		key, ok := isSafe(env)
		if !ok {
			continue
		}
		if !seen[key] {
			sanitized = append(sanitized, env)
			seen[key] = true
		}
	}

	return sanitized
}
