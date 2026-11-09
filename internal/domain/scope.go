// Package domain 은 OAuth 2.1 스코프(Scope) 문자열과 요청된 액션/리소스 간의 최소 권한(Least Privilege) 매칭 로직을 제공한다.
package domain

import (
	"strings"
)

// ScopeMatches 는 공백으로 구분된 OAuth 2.1 scope 문자열이 요청된 (action, resource)를 허용하는지 판정하는 순수 함수다.
//
// [매칭 평가 규칙]:
// 1. 2단 액션 스코프 (예: "file:read", "file:write"):
//    - 해당 액션에 대한 전체 리소스 접근을 허용한다.
// 2. 3단 액션+리소스 한정 스코프 (예: "file:read:docs/plan.txt"):
//    - 액션과 정규화된 리소스 경로가 정확히 일치할 때만 인가한다.
// 3. 슈퍼유저/와일드카드 우회 원천 차단 (Fail-Closed):
//    - "*", "admin", "all" 등 암묵적 특권 확장을 일절 허용하지 않는다. 최소 권한 원칙(PoLP)에 따라 명시된 스코프만 유효하다.
func ScopeMatches(scopeStr string, action Action, resource string) bool {
	cleanScope := strings.TrimSpace(scopeStr)
	if cleanScope == "" {
		return false
	}

	cleanRes := strings.TrimPrefix(strings.TrimSpace(resource), "/")

	scopes := strings.Fields(cleanScope)
	for _, sc := range scopes {
		sc = strings.TrimSpace(sc)
		if sc == "" || sc == "*" || sc == "admin" {
			// 슈퍼유저 및 와일드카드 우회 배제 (Fail-Closed)
			continue
		}

		parts := strings.Split(sc, ":")
		if len(parts) == 2 {
			// 2단 스코프: "file:read"
			if Action(sc) == action {
				return true
			}
		} else if len(parts) >= 3 {
			// 3단 이상 스코프: "file:read:path/to/file"
			scAction := Action(parts[0] + ":" + parts[1])
			scRes := strings.TrimPrefix(strings.Join(parts[2:], ":"), "/")
			if scAction == action && scRes == cleanRes {
				return true
			}
		}
	}

	return false
}
