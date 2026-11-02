package domain_test

import (
	"testing"

	"authz-harness/internal/domain"
)

func TestScopeMatches(t *testing.T) {
	tests := []struct {
		name     string
		scopeStr string
		action   domain.Action
		resource string
		expected bool
	}{
		{
			name:     "2단 액션 스코프 일치 (file:read)",
			scopeStr: "file:read",
			action:   domain.ActionFileRead,
			resource: "docs/plan.txt",
			expected: true,
		},
		{
			name:     "2단 액션 스코프 불일치 (file:read 로 write 요청)",
			scopeStr: "file:read",
			action:   domain.ActionFileWrite,
			resource: "docs/plan.txt",
			expected: false,
		},
		{
			name:     "3단 리소스 한정 스코프 일치",
			scopeStr: "file:read:docs/plan.txt",
			action:   domain.ActionFileRead,
			resource: "docs/plan.txt",
			expected: true,
		},
		{
			name:     "3단 리소스 한정 스코프 경로 선두 슬래시 정규화 일치",
			scopeStr: "file:read:/docs/plan.txt",
			action:   domain.ActionFileRead,
			resource: "docs/plan.txt",
			expected: true,
		},
		{
			name:     "3단 리소스 한정 스코프 타 리소스 접근 차단",
			scopeStr: "file:read:docs/plan.txt",
			action:   domain.ActionFileRead,
			resource: "docs/secret.txt",
			expected: false,
		},
		{
			name:     "와일드카드 및 admin 슈퍼유저 우회 배제",
			scopeStr: "* admin",
			action:   domain.ActionFileWrite,
			resource: "docs/plan.txt",
			expected: false,
		},
		{
			name:     "다중 스코프 중 두 번째 스코프 매칭",
			scopeStr: "file:read:docs/a.txt file:write:docs/b.txt",
			action:   domain.ActionFileWrite,
			resource: "docs/b.txt",
			expected: true,
		},
		{
			name:     "빈 스코프 문자열 차단",
			scopeStr: "",
			action:   domain.ActionFileRead,
			resource: "docs/plan.txt",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := domain.ScopeMatches(tc.scopeStr, tc.action, tc.resource)
			if got != tc.expected {
				t.Fatalf("ScopeMatches(%q, %q, %q) = %v; want %v",
					tc.scopeStr, tc.action, tc.resource, got, tc.expected)
			}
		})
	}
}
