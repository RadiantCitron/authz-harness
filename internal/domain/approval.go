package domain

import (
	"fmt"
	"regexp"
	"time"
)

const (
	// DefaultApprovalTTL 은 승인 TTL 을 지정하지 않았을 때의 기본값이다.
	DefaultApprovalTTL = 5 * time.Minute

	// MaxApprovalTTL 은 승인 TTL 의 상한이다.
	MaxApprovalTTL = time.Hour
)

// Approval 은 사람이 내준 1회용 승인이다. 소비는 원장에서 지우는 것이므로 Consumed 필드는 없다.
type Approval struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	Action    Action    `json:"action"`
	Resource  string    `json:"resource"`
	TokenJTI  string    `json:"token_jti"`
	ArgHash   string    `json:"arg_hash,omitempty"` // 비면 인자 바인딩 없음
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ApprovalBinding 은 승인이 묶여야 하는 요청의 식별 요소다.
type ApprovalBinding struct {
	Subject  string
	Action   Action
	Resource string
	TokenJTI string
	ArgHash  string
}

// Matches 는 승인이 요청 바인딩에 맞는지 판정하는 순수 함수다 (PDP·소비 경로 공통 규칙).
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

// SelectApproval 은 승인 목록에서 요청에 맞는 승인을 고르는 단일 원천이다.
// 맞는 승인이 있으면 첫 번째 ID 와 AUTHORIZED 를, 없으면 같은 주체 승인의 상태에 따라
// APPROVAL_EXPIRED > APPROVAL_MISMATCH > APPROVAL_REQUIRED 순으로 사유를 돌려준다(id 는 "").
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

// ValidateApprovalTTL 은 0 이면 기본값을, 음수이거나 상한 초과이면 INVALID_ARGUMENTS 오류를 돌려준다.
func ValidateApprovalTTL(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		return DefaultApprovalTTL, nil
	}
	if ttl < 0 || ttl > MaxApprovalTTL {
		return 0, NewError(ReasonInvalidArguments, "approval", fmt.Sprintf("approval ttl must be within (0, %s]", MaxApprovalTTL), nil)
	}
	return ttl, nil
}

var argHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateArgHash 는 ""(인자 바인딩 없음) 또는 DataDigest 형식만 허용한다.
// 빈 페이로드는 DataDigest 가 ""를 내므로 인자 바인딩을 걸 수 없다(문서화된 한계).
func ValidateArgHash(s string) error {
	if s == "" || argHashPattern.MatchString(s) {
		return nil
	}
	return NewError(ReasonInvalidArguments, "approval", "arg_hash must be empty or sha256:<64 hex>", nil)
}
