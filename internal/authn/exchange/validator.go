// Package exchange 는 RFC 8693 OAuth 2.0 Token Exchange 기반의 권한 축소 위임(Downscoping) 불변식 검증기를 제공한다.
//
// [5대 축소 위임 불변식 (Delegation Invariants)]
// 1. 스코프 부분집합 원칙 (Scope Subset):
//    - 자식 토큰의 요청 스코프 집합은 반드시 부모 토큰 스코프 집합의 부분집합이어야 한다 ($S_{child} \subseteq S_{parent}$).
//    - 부모에 없는 권한을 자식이 요청하면 ReasonDelegationScopeExceeded 로 즉시 차단된다.
// 2. 수명 상한 불변식 (TTL Invariant):
//    - 자식 토큰의 만료 시각(exp)은 부모 토큰의 만료 시각을 절대 초과할 수 없다 ($exp_{child} \le exp_{parent}$).
// 3. 최대 위임 깊이 강제 (Depth Limit):
//    - 위임 체인의 깊이는 MaxDelegationDepth(3)를 초과할 수 없다. 무한 위임 체인으로 인한 권한 남용을 방지한다.
// 4. 순환 위임 원천 차단 (Self-Loop Prevention):
//    - 자식 주체(childSub)가 부모 주체와 동일하거나, 조상 act 계보 사슬 내에 이미 존재하는 경우 순환 위임 공격으로 간주하여 차단한다.
// 5. 예산 단조 축소 (Budget Downscope):
//    - 자식 토큰의 예산은 부모 잔여 예산 이내여야 하며, 부모가 예산 토큰일 때 자식이 예산 없이(무제한) 요청하는 격상을 금지한다.
package exchange

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/domain"
)

// MaxDelegationDepth 는 허용되는 최대 위임 체인 깊이다 (루트 0 ➔ 1차 자식 1 ➔ 2차 자식 2 ➔ 3차 자식 3).
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

// DownscopeValidator 는 권한 축소 및 위임 불변식을 검증하는 DIP 인터페이스다.
type DownscopeValidator interface {
	ValidateDownscope(parentClaims *domain.TokenClaims, childSub, requestedScope string, childTTL time.Duration, now time.Time) error
}

// DefaultDownscopeValidator 는 표준 DownscopeValidator 구현체다.
type DefaultDownscopeValidator struct {
	maxDepth int
}

// NewDownscopeValidator 는 기본 최대 깊이(3)를 갖는 DefaultDownscopeValidator 인스턴스를 반환한다.
func NewDownscopeValidator() *DefaultDownscopeValidator {
	return &DefaultDownscopeValidator{
		maxDepth: MaxDelegationDepth,
	}
}

// ParseScopes 는 공백으로 구분된 OAuth 2.1 스코프 문자열을 중복이 제거된 정규화 슬라이스로 분리한다.
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

// ValidateDownscope 는 RFC 8693 및 최소 권한 위임 불변식(스코프, 수명, 깊이, 순환 루프)을 검증한다.
func (v *DefaultDownscopeValidator) ValidateDownscope(parentClaims *domain.TokenClaims, childSub, requestedScope string, childTTL time.Duration, now time.Time) error {
	if parentClaims == nil {
		return errors.New("parent claims cannot be nil")
	}

	// 1. Scope 공백 검사
	childScopes := ParseScopes(requestedScope)
	if len(childScopes) == 0 {
		return domain.NewError(domain.ReasonDelegationScopeEmpty, "requested scope is empty", ErrScopeEmpty)
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
		return domain.NewError(domain.ReasonDelegationScopeExceeded, fmt.Sprintf("[%s] not in parent scopes", strings.Join(exceededScopes, ", ")), ErrScopeExceeded)
	}

	// 3. 만료 시각 상한 검증 ($exp_{child} \le exp_{parent}$)
	if childTTL <= 0 {
		childTTL = 1 * time.Hour
	}
	childExp := now.Add(childTTL).Unix()
	if childExp > parentClaims.ExpiresAt {
		return domain.NewError(domain.ReasonDelegationTTLExceeded, fmt.Sprintf("child exp (%d) > parent exp (%d)", childExp, parentClaims.ExpiresAt), ErrTTLExceeded)
	}

	// 4. 위임 깊이 검증 (DelegationDepth + 1 <= MaxDepth)
	nextDepth := parentClaims.DelegationDepth + 1
	if nextDepth > v.maxDepth {
		return domain.NewError(domain.ReasonDelegationDepthExceeded, fmt.Sprintf("next depth %d exceeds max %d", nextDepth, v.maxDepth), ErrDepthExceeded)
	}

	// 5. 순환 위임 검증 (부모 sub == 자식 sub 또는 이전 act 체인에 존재)
	cleanChildSub := strings.TrimSpace(childSub)
	if cleanChildSub == "" {
		return errors.New("child subject is required")
	}
	if cleanChildSub == parentClaims.Subject {
		return domain.NewError(domain.ReasonDelegationSelfLoop, fmt.Sprintf("child subject matches parent subject %s", cleanChildSub), ErrSelfLoop)
	}

	currActor := parentClaims.Actor
	for currActor != nil {
		if currActor.Subject == cleanChildSub {
			return domain.NewError(domain.ReasonDelegationSelfLoop, fmt.Sprintf("child subject %s already exists in actor chain", cleanChildSub), ErrSelfLoop)
		}
		currActor = currActor.Actor
	}

	return nil
}

// ValidateBudgetDownscope 는 예산 단조 축소(자식 <= 부모 클레임 상한)를 정적으로 검증한다.
// 부모 예산 없이 자식만 예산을 요청하면 예약할 부모 엔트리가 없으므로 거부한다 (예산은 루트 발급에서만 시작).
// 부모만 예산이 있고 자식이 없으면 무제한 격상이므로 거부한다.
func ValidateBudgetDownscope(parent, child *domain.Budget) error {
	deny := func(msg string) error {
		return domain.NewError(domain.ReasonDelegationBudgetExceeded, msg, nil)
	}
	switch {
	case parent == nil && child == nil:
		return nil
	case parent == nil:
		return deny("child budget requested but parent has no budget")
	case child == nil:
		return deny("child must carry a budget when parent has one")
	}
	if err := child.Validate(); err != nil {
		return err
	}
	if !child.Within(*parent) {
		return deny("child budget exceeds parent budget")
	}
	return nil
}
