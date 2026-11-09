// Package domain 은 주체에게 리소스 접근 권한을 부여하는 인가 정책의 최소 단위인 Grant 엔티티 및 표준 Action 을 정의한다.
//
// [Action 확장 규칙 (신규 도구 추가 시 정비 지침)]
// 1. 도메인 상수 추가: 본 파일의 Action 상수에 ActionDBQuery Action = "db:query" 추가 및 IsValidAction() 등록.
// 2. 도구 구현: internal/authz/pep/ 에 Tool 인터페이스를 구현하는 새 파일 작성 (Prepare, CheckBoundary, Execute).
// 3. 도구 레지스트리 바인딩: internal/authz/pep/tool.go 의 tools 맵에 등록.
// 이 3단계만 거치면 게이트웨이 파이프라인(10단계 검문소) 수정 없이 즉시 인가/격리/예산/감사 가드레일이 자동 적용된다.
// (참조: docs/작동원리/005-아키텍처_배선지도와_빠른_코드인수인계.md §3)
package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// GrantStatus 는 인가 권한 부여의 수명주기 상태다.
type GrantStatus string

const (
	// GrantStatusActive 는 권한이 현재 정상 활성화되어 인가에 사용 가능한 상태다.
	GrantStatusActive GrantStatus = "active"

	// GrantStatusRevoked 는 권한이 명시적으로 회수되어 효력을 상실한 상태다 (PDP 인가 거부).
	GrantStatusRevoked GrantStatus = "revoked"
)

// Action 은 인가 주체가 리소스에 수행하려는 보호된 행위의 공식 식별자다.
type Action string

const (
	// ActionFileRead 는 파일 또는 디렉터리 읽기 행위다 (file:read).
	ActionFileRead Action = "file:read"

	// ActionFileWrite 는 파일 생성, 덮어쓰기, 수정 행위다 (file:write).
	ActionFileWrite Action = "file:write"

	// ActionNetFetch 는 인가된 로컬 루프백 호스트로의 HTTP GET 송신 행위다 (net:fetch).
	ActionNetFetch Action = "net:fetch"

	// ActionExecRun 은 화이트리스트에 사전 고정된 격리 실행 파일 실행 행위다 (exec:run).
	ActionExecRun Action = "exec:run"
)

// IsValidAction 은 action 이 등록된 공식 4종 액션 중 하나인지 검증한다.
func IsValidAction(a Action) bool {
	switch a {
	case ActionFileRead, ActionFileWrite, ActionNetFetch, ActionExecRun:
		return true
	}
	return false
}

// ParseAction 은 사용자 CLI 입력 문자열을 정식 Action 상수로 파싱하고 정규화한다.
// "read" ➔ ActionFileRead, "write" ➔ ActionFileWrite 와 같은 편의 별칭을 지원한다.
func ParseAction(s string) (Action, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "read":
		return ActionFileRead, nil
	case "write":
		return ActionFileWrite, nil
	default:
		if a := Action(v); IsValidAction(a) {
			return a, nil
		}
		return "", fmt.Errorf("invalid action: %q (must be file:read, file:write, net:fetch or exec:run)", s)
	}
}

var (
	ErrEmptyGrantID   = errors.New("grant: id is required")
	ErrEmptySubject   = errors.New("grant: subject is required")
	ErrEmptyAction    = errors.New("grant: action is required")
	ErrInvalidAction  = errors.New("grant: action must be file:read, file:write, net:fetch or exec:run")
	ErrEmptyResource  = errors.New("grant: resource is required")
	ErrInvalidStatus  = errors.New("grant: invalid status")
	ErrRelativeEscape = errors.New("grant: resource path must not contain parent directory traversal (..)")
)

// Grant 는 특정 주체(Subject)에게 특정 리소스(Resource)에 대한 액션(Action) 수행을 허가하는 불변 정책 엔티티다.
// JSON 파일(state.json)에 영속화되며 PDP 가 메모리 스냅샷으로 읽어 인가를 판정한다.
type Grant struct {
	// ID 는 권한 부여의 고유 식별자다 (UUIDv4).
	ID string `json:"id"`

	// Subject 는 권한을 부여받은 주체 식별자다 (예: "worker-01").
	Subject string `json:"subject"`

	// Action 은 허용된 행위다 (ActionFileRead, ActionFileWrite 등).
	Action Action `json:"action"`

	// Resource 는 허용된 대상 리소스 경로다 (예: "tasks.txt", "data/*").
	Resource string `json:"resource"`

	// Status 는 현재 권한 상태다 (active, revoked).
	Status GrantStatus `json:"status"`

	// CreatedAt 은 권한이 최초 부여된 시각이다.
	CreatedAt time.Time `json:"created_at"`

	// RevokedAt 은 권한이 회수된 시각이다 (회수되지 않았으면 nil).
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// RequiresApproval 이 true 면 이 Grant 에 매칭되더라도 즉시 허용(allow)되지 않고
	// 사람의 수동 1회용 승인(Approval) 티켓을 요구하는 ask 판정이 내려진다.
	RequiresApproval bool `json:"requires_approval,omitempty"`
}

// Validate 는 Grant 엔티티의 필수 필드, 액션 유효성, 그리고 경로 탈출(../) 금지 불변식을 검증한다.
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
	if !IsValidAction(g.Action) {
		return ErrInvalidAction
	}
	if strings.TrimSpace(g.Resource) == "" {
		return ErrEmptyResource
	}

	// 경로 순회(..) 방어 검증 (보안 불변식)
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

// IsActive 는 해당 Grant 가 현재 취소되지 않고 유효하게 활성화되어 있는지 여부를 판정한다.
func (g *Grant) IsActive() bool {
	return g.Status == GrantStatusActive && g.RevokedAt == nil
}

// Revoke 는 해당 Grant 를 즉시 회수 상태(revoked)로 변경하고 현재 시각을 회수 시각으로 기록한다.
func (g *Grant) Revoke(now time.Time) {
	g.Status = GrantStatusRevoked
	t := now.UTC()
	g.RevokedAt = &t
}
