// Package domain 은 사람(운영자/관리자)이 사전에 발행하는 1회용 수동 승인(Approval) 티켓 모델 및 바인딩 규칙을 정의한다.
//
// [승인 티켓 설계 원칙]
// 1. 완전 바인딩 (Full Binding):
//    - 승인 티켓은 주체(Subject), 액션(Action), 대상 리소스(Resource), 토큰 고유ID(TokenJTI), 그리고 도구 인자 지문(ArgHash)에
//      철저히 결속(Binding)된다. 이 중 하나라도 일치하지 않으면 ReasonApprovalMismatch 로 거부된다.
// 2. 1회용 소비와 상태 불변 (One-Time Consumption):
//    - 승인이 집행(PEP 6단계 approval)되면 원장(authz/state.Store)에서 해당 티켓이 물리적으로 영구 삭제된다.
//      따라서 Approval 구조체 자체에는 `consumed: bool` 필드가 필요 없다.
// 3. TTL 유효기간 강제 (Default 5분, Max 1시간):
//    - 승인은 발행 후 짧은 유효기간 내에만 소비될 수 있으며, 만료 시 ReasonApprovalExpired 로 안전 거부된다 (Fail-Closed).
//
// [조립 및 처리처 상호 참조 (Cross-Referencing)]
// - 승인 발행 (PAP): internal/authz/pap/service.go (IssueApproval)
// - 승인 판단 (PDP): internal/authz/pdp/service.go (Evaluate 에서 ask 판정 또는 승인 대조)
// - 승인 집행/소비 (PEP): internal/authz/pep/gateway.go (assemble 의 StageApproval 단계)
package domain

import (
	"fmt"
	"regexp"
	"time"
)

const (
	// DefaultApprovalTTL 은 승인 티켓 생성 시 TTL 을 지정하지 않았을 때 적용되는 기본 수명(5분)이다.
	DefaultApprovalTTL = 5 * time.Minute

	// MaxApprovalTTL 은 승인 티켓이 가질 수 있는 수명의 절대 상한(1시간)이다.
	MaxApprovalTTL = time.Hour
)

// Approval 은 사람이 사전에 내준 1회용 수동 승인 티켓 모델이다.
type Approval struct {
	// ID 는 승인 티켓의 전역 고유 식별자다 (UUIDv4).
	ID string `json:"id"`

	// Subject 는 이 승인을 사용할 수 있는 인가 주체 식별자다 (예: "worker-01").
	Subject string `json:"subject"`

	// Action 은 승인된 도구 행위다 (예: "file:write").
	Action Action `json:"action"`

	// Resource 는 승인된 대상 리소스 경로다 (예: "tasks.txt").
	Resource string `json:"resource"`

	// TokenJTI 는 이 승인이 귀속된 특정 토큰의 고유 ID 다. 다른 토큰으로는 이 승인을 소비할 수 없다.
	TokenJTI string `json:"token_jti"`

	// ArgHash 는 도구 입력 인자의 SHA-256 지문(DataDigest)이다.
	// 비어 있으면 인자 바인딩 없이 (Action, Resource, JTI) 만 일치하면 통과한다.
	ArgHash string `json:"arg_hash,omitempty"`

	// CreatedAt 은 승인이 발행된 시각이다.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt 은 승인의 효력이 만료되는 시각이다.
	ExpiresAt time.Time `json:"expires_at"`
}

// ApprovalBinding 은 인가 관문에 인입된 요청이 승인 티켓과 대조되어야 하는 식별 요소 집합이다.
type ApprovalBinding struct {
	Subject  string
	Action   Action
	Resource string
	TokenJTI string
	ArgHash  string
}

// Matches 는 단일 승인 티켓이 요청 바인딩 b 에 부합하는지 판정하는 순수 함수다.
// PDP 판단 경로와 PEP 소비 경로에서 동일한 단일 진실 규칙으로 호출된다.
func (a Approval) Matches(b ApprovalBinding, now time.Time) Reason {
	if a.Subject != b.Subject || a.Action != b.Action || a.Resource != b.Resource || a.TokenJTI != b.TokenJTI {
		return ReasonApprovalMismatch
	}
	if a.ArgHash != "" && a.ArgHash != b.ArgHash {
		return ReasonApprovalMismatch
	}
	if !now.Before(a.ExpiresAt) {
		return ReasonApprovalExpired
	}
	return ReasonAuthorized
}

// SelectApproval 은 활성 승인 목록에서 주어진 요청 바인딩 b 에 일치하는 최적의 승인을 고르는 단일 원천 알고리즘이다.
//
// [선택 및 우선순위 알고리즘]
// 1. 일치하는 유효 승인이 있으면: 해당 승인 ID 와 ReasonAuthorized 를 반환한다.
// 2. 일치하는 유효 승인이 없으면 사유를 구체화하여 보고한다:
//    - 동일 주체에 만료된 승인이 존재하는 경우: ReasonApprovalExpired 반환.
//    - 동일 주체에 파라미터가 불일치하는 승인이 있는 경우: ReasonApprovalMismatch 반환.
//    - 아무런 관련 승인도 없는 경우: ReasonApprovalRequired 반환 (사람 승인 요청 필요).
func SelectApproval(approvals []Approval, b ApprovalBinding, now time.Time) (string, Reason) {
	sawExpired, sawMismatch := false, false
	for _, a := range approvals {
		switch a.Matches(b, now) {
		case ReasonAuthorized:
			return a.ID, ReasonAuthorized
		case ReasonApprovalExpired:
			if a.Subject == b.Subject {
				sawExpired = true
			}
		case ReasonApprovalMismatch:
			if a.Subject == b.Subject {
				sawMismatch = true
			}
		}
	}
	switch {
	case sawExpired:
		return "", ReasonApprovalExpired
	case sawMismatch:
		return "", ReasonApprovalMismatch
	}
	return "", ReasonApprovalRequired
}

// ValidateApprovalTTL 은 요청된 TTL 기간의 유효성을 검증하고 기본값을 정규화한다.
// 0 이면 DefaultApprovalTTL(5분)을 반환하고, 음수이거나 MaxApprovalTTL(1시간)을 초과하면 에러를 반환한다.
func ValidateApprovalTTL(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		return DefaultApprovalTTL, nil
	}
	if ttl < 0 || ttl > MaxApprovalTTL {
		return 0, NewError(ReasonInvalidArguments, fmt.Sprintf("approval ttl must be within (0, %s]", MaxApprovalTTL), nil)
	}
	return ttl, nil
}

// argHashPattern 은 64자리 16진수 SHA-256 포맷을 검증하는 정규식이다.
var argHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateArgHash 는 인자 해시 문자열이 비어있거나(인자 바인딩 미사용), 유효한 DataDigest 형식인지 검증한다.
func ValidateArgHash(s string) error {
	if s == "" || argHashPattern.MatchString(s) {
		return nil
	}
	return NewError(ReasonInvalidArguments, "arg_hash must be empty or sha256:<64 hex>", nil)
}
