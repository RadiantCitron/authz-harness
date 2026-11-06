package pap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

var (
	ErrGrantNotFound = errors.New("pap: grant not found")
)

// CreateGrantRequest 는 권한 신규 발급 요청 명세다.
type CreateGrantRequest struct {
	Subject  string        `json:"subject"`
	Action   domain.Action `json:"action"`
	Resource string        `json:"resource"`

	// RequiresApproval 이 true 이면 이 Grant 로 허용되는 요청도 사람 승인이 필요하다(ask).
	RequiresApproval bool `json:"requires_approval,omitempty"`
}

// CreateApprovalRequest 는 사람 승인 발급 요청 명세다. ArgHash 가 비면 인자 바인딩이 없다.
type CreateApprovalRequest struct {
	Subject  string
	Action   domain.Action
	Resource string
	TokenJTI string
	ArgHash  string
	TTL      time.Duration // 0 이면 기본값(5m)
}

// GrantFilter 는 권한 목록 조회 시 필터 조건이다.
type GrantFilter struct {
	Subject string              `json:"subject,omitempty"`
	Status  *domain.GrantStatus `json:"status,omitempty"`
}

// Service 는 정책 관리점(PAP)의 핵심 관리 규약이다.
type Service interface {
	// CreateGrant 는 주체에게 특정 리소스/액션의 활성 권한을 발급하고 감사 로그를 남긴다.
	CreateGrant(ctx context.Context, req CreateGrantRequest) (*domain.Grant, error)

	// RevokeGrant 는 특정 ID의 권한을 즉시 회수 상태로 변경하고 감사 로그를 남긴다.
	RevokeGrant(ctx context.Context, grantID string) (*domain.Grant, error)

	// BumpEpoch 는 주체의 Security Epoch를 1 증가시켜 이전 권한/토큰을 일괄 무효화하고 감사 로그를 남긴다.
	BumpEpoch(ctx context.Context, subject string) (domain.Epoch, error)

	// ListGrants 는 조건에 부합하는 Grant 목록을 반환한다.
	ListGrants(ctx context.Context, filter GrantFilter) ([]domain.Grant, error)

	// CreateApproval 은 (주체, 액션, 리소스, jti, 선택적 arg_hash)에 묶인 1회용 승인을 발급하고 감사 로그를 남긴다.
	CreateApproval(ctx context.Context, req CreateApprovalRequest) (*domain.Approval, error)

	// ListApprovals 는 승인 목록을 반환한다(subject 가 비면 전체).
	ListApprovals(ctx context.Context, subject string) ([]domain.Approval, error)
}

// papService 는 PAP Service의 기본 구현체다.
type papService struct {
	store state.Store
	audit audit.Writer
	clock domain.Clock
}

// ServiceOption 은 PAP Service 구성 옵션이다.
type ServiceOption func(*papService)

// WithClock 은 가상 시계를 주입하기 위한 옵션이다.
func WithClock(c domain.Clock) ServiceOption {
	return func(s *papService) {
		if c != nil {
			s.clock = c
		}
	}
}

// NewService 는 PAP 서비스를 생성한다.
func NewService(store state.Store, auditWriter audit.Writer, opts ...ServiceOption) Service {
	s := &papService{
		store: store,
		audit: auditWriter,
		clock: domain.RealClock{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CreateGrant 는 신규 활성 Grant를 생성하고 감사 로그를 기록한다.
func (s *papService) CreateGrant(ctx context.Context, req CreateGrantRequest) (*domain.Grant, error) {
	now := s.clock.Now().UTC()
	grant := &domain.Grant{
		ID:        fmt.Sprintf("grant-%d", now.UnixNano()),
		Subject:   strings.TrimSpace(req.Subject),
		Action:    req.Action,
		Resource:  strings.TrimSpace(req.Resource),
		Status:    domain.GrantStatusActive,
		CreatedAt: now,

		RequiresApproval: req.RequiresApproval,
	}

	if err := grant.Validate(); err != nil {
		return nil, domain.NewError(domain.ReasonInvalidArguments, "pap: validation failed", err)
	}

	err := s.store.Update(func(st *state.GrantsState) error {
		st.Grants = append(st.Grants, *grant)
		return nil
	})
	if err != nil {
		return nil, domain.NewError(domain.ReasonInternalError, "pap: failed to store grant", err)
	}

	// 감사 이벤트 기록 (실패 시 방금 추가한 Grant 를 롤백하여 무증거 상태 변경 방지)
	if s.audit != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   fmt.Sprintf("pap-create-%s", grant.ID),
			Step:      "pap.create_grant",
			Actor:     "admin",
			Action:    "grant.created",
			Resource:  grant.Resource,
			Decision:  "allow",
			Success:   true,
			Metadata: map[string]interface{}{
				"grant_id": grant.ID,
				"subject":  grant.Subject,
				"action":   string(grant.Action),

				"requires_approval": grant.RequiresApproval,
			},
		}
		if err := s.audit.Log(auditEv); err != nil {
			_ = s.store.Update(func(st *state.GrantsState) error {
				for i := len(st.Grants) - 1; i >= 0; i-- {
					if st.Grants[i].ID == grant.ID {
						st.Grants = append(st.Grants[:i], st.Grants[i+1:]...)
						break
					}
				}
				return nil
			})
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "pap: audit logging failed", err)
		}
	}

	return grant, nil
}

// RevokeGrant 는 특정 ID의 Grant를 회수(Revoke) 상태로 갱신하고 감사 로그를 기록한다.
func (s *papService) RevokeGrant(ctx context.Context, grantID string) (*domain.Grant, error) {
	cleanID := strings.TrimSpace(grantID)
	if cleanID == "" {
		return nil, domain.NewError(domain.ReasonInvalidArguments, "pap: grant id required", domain.ErrEmptyGrantID)
	}

	now := s.clock.Now().UTC()
	var revokedGrant *domain.Grant
	var prevStatus domain.GrantStatus
	var prevRevokedAt *time.Time

	err := s.store.Update(func(st *state.GrantsState) error {
		for i := range st.Grants {
			if st.Grants[i].ID == cleanID {
				prevStatus = st.Grants[i].Status
				prevRevokedAt = st.Grants[i].RevokedAt
				st.Grants[i].Revoke(now)
				gCopy := st.Grants[i]
				revokedGrant = &gCopy
				return nil
			}
		}
		return ErrGrantNotFound
	})
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return nil, domain.NewError(domain.ReasonInvalidArguments, "pap: grant not found", ErrGrantNotFound)
		}
		return nil, domain.NewError(domain.ReasonInternalError, "pap: failed to revoke grant", err)
	}

	// 감사 이벤트 기록 (실패 시 이전 상태로 롤백하여 무증거 회수 방지)
	if s.audit != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   fmt.Sprintf("pap-revoke-%s", revokedGrant.ID),
			Step:      "pap.revoke_grant",
			Actor:     "admin",
			Action:    "grant.revoked",
			Resource:  revokedGrant.Resource,
			Decision:  "allow",
			Success:   true,
			Metadata: map[string]interface{}{
				"grant_id":   revokedGrant.ID,
				"subject":    revokedGrant.Subject,
				"revoked_at": now.Format(time.RFC3339),
			},
		}
		if err := s.audit.Log(auditEv); err != nil {
			_ = s.store.Update(func(st *state.GrantsState) error {
				for i := range st.Grants {
					if st.Grants[i].ID == cleanID {
						st.Grants[i].Status = prevStatus
						st.Grants[i].RevokedAt = prevRevokedAt
						break
					}
				}
				return nil
			})
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "pap: audit logging failed", err)
		}
	}

	return revokedGrant, nil
}

// BumpEpoch 는 대상 주체의 Security Epoch를 1 증가시키고 감사 로그를 기록한다.
func (s *papService) BumpEpoch(ctx context.Context, subject string) (domain.Epoch, error) {
	cleanSub := strings.TrimSpace(subject)
	if cleanSub == "" {
		return 0, domain.NewError(domain.ReasonInvalidArguments, "pap: subject required", domain.ErrEmptySubject)
	}

	var newEpoch domain.Epoch
	var prevEpoch domain.Epoch
	now := s.clock.Now().UTC()

	err := s.store.Update(func(st *state.GrantsState) error {
		if st.Epochs == nil {
			st.Epochs = make(domain.SecurityEpochs)
		}
		prevEpoch = st.Epochs.Get(cleanSub)
		newEpoch = st.Epochs.Bump(cleanSub)
		return nil
	})
	if err != nil {
		return 0, domain.NewError(domain.ReasonInternalError, "pap: failed to bump epoch", err)
	}

	// 감사 이벤트 기록 (실패 시 이전 Epoch 로 롤백하여 무증거 변경 방지)
	if s.audit != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   fmt.Sprintf("pap-epoch-%s-%d", cleanSub, newEpoch),
			Step:      "pap.bump_epoch",
			Actor:     "admin",
			Action:    "epoch.bumped",
			Success:   true,
			Metadata: map[string]interface{}{
				"subject":        cleanSub,
				"previous_epoch": int64(prevEpoch),
				"new_epoch":      int64(newEpoch),
			},
		}
		if err := s.audit.Log(auditEv); err != nil {
			_ = s.store.Update(func(st *state.GrantsState) error {
				if st.Epochs != nil {
					st.Epochs[cleanSub] = prevEpoch
				}
				return nil
			})
			return 0, domain.NewError(domain.ReasonAuditLogFailed, "pap: audit logging failed", err)
		}
	}

	return newEpoch, nil
}

// ListGrants 는 필터 조건에 부합하는 Grant 목록을 반환한다.
func (s *papService) ListGrants(ctx context.Context, filter GrantFilter) ([]domain.Grant, error) {
	st, err := s.store.Load()
	if err != nil {
		return nil, fmt.Errorf("pap: failed to load state: %w", err)
	}

	result := make([]domain.Grant, 0)
	for _, g := range st.Grants {
		if filter.Subject != "" && g.Subject != filter.Subject {
			continue
		}
		if filter.Status != nil && g.Status != *filter.Status {
			continue
		}
		result = append(result, g)
	}

	return result, nil
}

// CreateApproval 은 TTL·ArgHash 를 검증하고 승인을 원장에 저장한 뒤 approval.granted 감사를 남긴다.
func (s *papService) CreateApproval(ctx context.Context, req CreateApprovalRequest) (*domain.Approval, error) {
	ttl, err := domain.ValidateApprovalTTL(req.TTL)
	if err != nil {
		return nil, err
	}
	if err := domain.ValidateArgHash(req.ArgHash); err != nil {
		return nil, err
	}
	sub, res, jti := strings.TrimSpace(req.Subject), strings.TrimSpace(req.Resource), strings.TrimSpace(req.TokenJTI)
	if sub == "" || strings.TrimSpace(string(req.Action)) == "" || res == "" || jti == "" {
		return nil, domain.NewError(domain.ReasonInvalidArguments, "pap: approval requires subject, action, resource, jti", nil)
	}

	now := s.clock.Now().UTC()
	a := domain.Approval{
		ID:        fmt.Sprintf("approval-%d", now.UnixNano()),
		Subject:   sub,
		Action:    req.Action,
		Resource:  res,
		TokenJTI:  jti,
		ArgHash:   req.ArgHash,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := state.CreateApproval(s.store, a, now); err != nil {
		return nil, domain.NewError(domain.ReasonInternalError, "pap: failed to store approval", err)
	}

	// 감사는 잠금(Update)을 반환한 뒤에만 기록하며, 실패 시 방금 추가한 승인을 롤백한다.
	if s.audit != nil {
		ev := audit.Event{
			Timestamp: now,
			TraceID:   fmt.Sprintf("pap-approval-%s", a.ID),
			Step:      "pap.create_approval",
			Actor:     "admin",
			Action:    "approval.granted",
			Resource:  a.Resource,
			Decision:  "allow",
			TokenJTI:  a.TokenJTI,
			ArgHash:   a.ArgHash,
			Success:   true,
			Metadata: map[string]interface{}{
				"approval_id": a.ID,
				"subject":     a.Subject,
				"action":      string(a.Action),
				"token_jti":   a.TokenJTI,
				"arg_hash":    a.ArgHash,
				"expires_at":  a.ExpiresAt.Format(time.RFC3339),
			},
		}
		if err := s.audit.Log(ev); err != nil {
			_ = s.store.Update(func(st *state.GrantsState) error {
				for i := len(st.Approvals) - 1; i >= 0; i-- {
					if st.Approvals[i].ID == a.ID {
						st.Approvals = append(st.Approvals[:i], st.Approvals[i+1:]...)
						break
					}
				}
				return nil
			})
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "pap: audit logging failed", err)
		}
	}
	return &a, nil
}

// ListApprovals 는 승인 목록을 반환한다(subject 가 비면 전체).
func (s *papService) ListApprovals(ctx context.Context, subject string) ([]domain.Approval, error) {
	st, err := s.store.Load()
	if err != nil {
		return nil, fmt.Errorf("pap: failed to load state: %w", err)
	}
	out := make([]domain.Approval, 0)
	for _, a := range st.Approvals {
		if subject != "" && a.Subject != subject {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}
