package domain

import (
	"errors"
	"strings"
	"time"
)

// GrantStatus 는 권한 부여의 상태를 정의한다.
type GrantStatus string

const (
	// GrantStatusActive 는 권한이 유효하게 활성화된 상태다.
	GrantStatusActive GrantStatus = "active"

	// GrantStatusRevoked 는 권한이 명시적으로 회수되어 효력을 상실한 상태다.
	GrantStatusRevoked GrantStatus = "revoked"
)

// Action 은 주체가 리소스에 수행하려는 행위를 식별한다.
type Action string

const (
	// ActionFileRead 는 파일 또는 디렉터리 읽기 행위다.
	ActionFileRead Action = "file:read"

	// ActionFileWrite 는 파일 쓰기 또는 수정 행위다.
	ActionFileWrite Action = "file:write"
)

var (
	ErrEmptyGrantID   = errors.New("grant: id is required")
	ErrEmptySubject   = errors.New("grant: subject is required")
	ErrEmptyAction    = errors.New("grant: action is required")
	ErrEmptyResource  = errors.New("grant: resource is required")
	ErrInvalidStatus  = errors.New("grant: invalid status")
	ErrRelativeEscape = errors.New("grant: resource path must not contain parent directory traversal (..)")
)

// Grant 는 특정 주체(Subject)에게 특정 리소스(Resource)에 대한 액션(Action) 수행을 허가하는 권한 부여 엔티티다.
type Grant struct {
	ID        string      `json:"id"`
	Subject   string      `json:"subject"`
	Action    Action      `json:"action"`
	Resource  string      `json:"resource"`
	Status    GrantStatus `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	RevokedAt *time.Time  `json:"revoked_at,omitempty"`

	// RequiresApproval 이 true 이면 이 Grant 로 허용되는 요청도 사람 승인이 있어야 한다(ask).
	RequiresApproval bool `json:"requires_approval,omitempty"`
}

// Validate 는 Grant 엔티티의 필수 필드 및 경로 규칙을 검증한다.
func (g *Grant) Validate() error {
	if strings.TrimSpace(g.ID) == "" {
		return ErrEmptyGrantID
	}
	if strings.TrimSpace(g.Subject) == "" {
		return ErrEmptySubject
	}
	if strings.TrimSpace(string(g.Action)) == "" {
		return ErrEmptyAction
	}
	if strings.TrimSpace(g.Resource) == "" {
		return ErrEmptyResource
	}

	// 경로 순회(..) 방어 검증
	if strings.Contains(g.Resource, "..") {
		return ErrRelativeEscape
	}

	switch g.Status {
	case GrantStatusActive, GrantStatusRevoked:
		// 유효한 상태
	default:
		return ErrInvalidStatus
	}

	return nil
}

// IsActive 는 해당 Grant가 현재 유효하게 활성화되어 있는지 여부를 반환한다.
func (g *Grant) IsActive() bool {
	return g.Status == GrantStatusActive && g.RevokedAt == nil
}

// Revoke 는 해당 Grant를 회수 상태로 변경하고 회수 시각을 기록한다.
func (g *Grant) Revoke(now time.Time) {
	g.Status = GrantStatusRevoked
	t := now.UTC()
	g.RevokedAt = &t
}
