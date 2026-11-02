package domain

import (
	"strings"
)

// ScopeMatches 는 공백으로 구분된 OAuth 2.1 scope 문자열이 요청된 (action, resource)를 허용하는지 판정하는 순수 함수다.
// 규칙:
// 1. "file:read" 또는 "file:write" (2단 액션 스코프): 해당 액션에 대한 접근 허용 (전체 리소스 대상)
// 2. "file:read:docs/plan.txt" (3단 액션+리소스 특정 스코프): 액션과 정규화된 리소스 경로가 정확히 일치할 때만 허용
// 3. 임의의 암묵적 슈퍼유저("*", "admin" 등) 우회는 허용하지 않는다 (Least Privilege 엄수).
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
			// 2단 액션 스코프: "file:read", "file:write"
			if Action(sc) == action {
				return true
			}
		} else if len(parts) >= 3 {
			// 3단 이상 액션+리소스 한정 스코프: "file:read:<path>"
			actPrefix := Action(parts[0] + ":" + parts[1])
			if actPrefix == action {
				scopePath := strings.TrimPrefix(strings.Join(parts[2:], ":"), "/")
				if scopePath == cleanRes {
					return true
				}
			}
		}
	}

	return false
}
