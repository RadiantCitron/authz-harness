package exchange

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/domain"
)

// MaxDelegationDepth 는 허용되는 최대 위임 체인 깊이다.
const MaxDelegationDepth = 3

var (
	// ErrScopeEmpty 는 요청 스코프가 비어있을 때 발생하는 에러다.
	ErrScopeEmpty = errors.New("requested scope is empty")

	// ErrScopeExceeded 는 자식 스코프가 부모 스코프를 초과할 때 발생하는 에러다.
	ErrScopeExceeded = errors.New("requested scope exceeds parent scope")

	// ErrTTLExceeded 는 자식 만료시간이 부모 잔여 시간을 초과할 때 발생하는 에러다.
	ErrTTLExceeded = errors.New("requested TTL exceeds parent expiration")

	// ErrDepthExceeded 는 위임 깊이 초과 에러다.
	ErrDepthExceeded = errors.New("delegation depth limit exceeded")

	// ErrSelfLoop 는 동일 주체 순환 위임 에러다.
	ErrSelfLoop = errors.New("self-loop delegation detected")
)

// DownscopeValidator 는 권한 축소 및 위임 불변식 검증 인터페이스다.
type DownscopeValidator interface {
	ValidateDownscope(parentClaims *domain.TokenClaims, childSub, requestedScope string, childTTL time.Duration, now time.Time) error
}

// DefaultDownscopeValidator 는 표준 DownscopeValidator 구현체다.
type DefaultDownscopeValidator struct {
	maxDepth int
}

// NewDownscopeValidator 는 DefaultDownscopeValidator 인스턴스를 반환한다.
func NewDownscopeValidator() *DefaultDownscopeValidator {
	return &DefaultDownscopeValidator{
		maxDepth: MaxDelegationDepth,
	}
}

// ParseScopes 는 공백으로 구분된 스코프 문자열을 정규화된 스코프 슬라이스로 분리한다.
func ParseScopes(scopeStr string) []string {
	fields := strings.Fields(scopeStr)
	if len(fields) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(fields))
	var result []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" && !seen[f] {
			seen[f] = true
			result = append(result, f)
		}
	}
	return result
}

// ValidateDownscope 는 RFC 8693 및 최소 권한 위임 불변식을 검증한다.
func (v *DefaultDownscopeValidator) ValidateDownscope(parentClaims *domain.TokenClaims, childSub, requestedScope string, childTTL time.Duration, now time.Time) error {
	if parentClaims == nil {
		return errors.New("parent claims cannot be nil")
	}

	// 1. Scope 공백 검사
	childScopes := ParseScopes(requestedScope)
	if len(childScopes) == 0 {
		return domain.NewError(domain.ReasonDelegationScopeEmpty, "downscope_validator", "requested scope is empty", ErrScopeEmpty)
	}

	// 2. Scope 부분집합 검증 ($S_{child} \subseteq S_{parent}$)
	parentScopes := ParseScopes(parentClaims.Scope)
	parentSet := make(map[string]bool, len(parentScopes))
	for _, s := range parentScopes {
		parentSet[s] = true
	}

	var exceededScopes []string
	for _, cs := range childScopes {
		if !parentSet[cs] {
			exceededScopes = append(exceededScopes, cs)
		}
	}
	if len(exceededScopes) > 0 {
		return domain.NewError(domain.ReasonDelegationScopeExceeded, "downscope_validator", fmt.Sprintf("[%s] not in parent scopes", strings.Join(exceededScopes, ", ")), ErrScopeExceeded)
	}

	// 3. 만료 시각 상한 검증 ($exp_{child} \le exp_{parent}$)
	if childTTL <= 0 {
		childTTL = 1 * time.Hour
	}
	childExp := now.Add(childTTL).Unix()
	if childExp > parentClaims.ExpiresAt {
		return domain.NewError(domain.ReasonDelegationTTLExceeded, "downscope_validator", fmt.Sprintf("child exp (%d) > parent exp (%d)", childExp, parentClaims.ExpiresAt), ErrTTLExceeded)
	}

	// 4. 위임 깊이 검증 (DelegationDepth + 1 <= MaxDepth)
	nextDepth := parentClaims.DelegationDepth + 1
	if nextDepth > v.maxDepth {
		return domain.NewError(domain.ReasonDelegationDepthExceeded, "downscope_validator", fmt.Sprintf("next depth %d exceeds max %d", nextDepth, v.maxDepth), ErrDepthExceeded)
	}

	// 5. 순환 위임 검증 (부모 sub == 자식 sub 또는 이전 act 체인에 존재)
	cleanChildSub := strings.TrimSpace(childSub)
	if cleanChildSub == "" {
		return errors.New("child subject is required")
	}
	if cleanChildSub == parentClaims.Subject {
		return domain.NewError(domain.ReasonDelegationSelfLoop, "downscope_validator", fmt.Sprintf("child subject matches parent subject %s", cleanChildSub), ErrSelfLoop)
	}

	currActor := parentClaims.Actor
	for currActor != nil {
		if currActor.Subject == cleanChildSub {
			return domain.NewError(domain.ReasonDelegationSelfLoop, "downscope_validator", fmt.Sprintf("child subject %s already exists in actor chain", cleanChildSub), ErrSelfLoop)
		}
		currActor = currActor.Actor
	}

	return nil
}
