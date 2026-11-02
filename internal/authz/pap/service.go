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
	}

	if err := grant.Validate(); err != nil {
		return nil, domain.NewError(domain.ReasonInvalidArguments, "pap", "pap: validation failed", err)
	}

	err := s.store.Update(func(st *state.GrantsState) error {
		st.Grants = append(st.Grants, *grant)
		return nil
	})
	if err != nil {
		return nil, domain.NewError(domain.ReasonInternalError, "pap", "pap: failed to store grant", err)
	}

	// 감사 이벤트 기록
	if s.audit != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   fmt.Sprintf("pap-create-%s", grant.ID),
			Step:      "pap.create_grant",
			Actor:     "admin",
			Action:    "grant.create",
			Resource:  grant.Resource,
			Decision:  "allow",
			Success:   true,
			Metadata: map[string]interface{}{
				"grant_id": grant.ID,
				"subject":  grant.Subject,
				"action":   string(grant.Action),
			},
		}
		if err := s.audit.Log(auditEv); err != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "pap", "pap: audit logging failed", err)
		}
	}

	return grant, nil
}

// RevokeGrant 는 특정 ID의 Grant를 회수(Revoke) 상태로 갱신하고 감사 로그를 기록한다.
func (s *papService) RevokeGrant(ctx context.Context, grantID string) (*domain.Grant, error) {
	cleanID := strings.TrimSpace(grantID)
	if cleanID == "" {
		return nil, domain.NewError(domain.ReasonInvalidArguments, "pap", "pap: grant id required", domain.ErrEmptyGrantID)
	}

	now := s.clock.Now().UTC()
	var revokedGrant *domain.Grant

	err := s.store.Update(func(st *state.GrantsState) error {
		for i := range st.Grants {
			if st.Grants[i].ID == cleanID {
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
			return nil, domain.NewError(domain.ReasonInvalidArguments, "pap", "pap: grant not found", ErrGrantNotFound)
		}
		return nil, domain.NewError(domain.ReasonInternalError, "pap", "pap: failed to revoke grant", err)
	}

	// 감사 이벤트 기록
	if s.audit != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   fmt.Sprintf("pap-revoke-%s", revokedGrant.ID),
			Step:      "pap.revoke_grant",
			Actor:     "admin",
			Action:    "grant.revoke",
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
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "pap", "pap: audit logging failed", err)
		}
	}

	return revokedGrant, nil
}

// BumpEpoch 는 대상 주체의 Security Epoch를 1 증가시키고 감사 로그를 기록한다.
func (s *papService) BumpEpoch(ctx context.Context, subject string) (domain.Epoch, error) {
	cleanSub := strings.TrimSpace(subject)
	if cleanSub == "" {
		return 0, domain.NewError(domain.ReasonInvalidArguments, "pap", "pap: subject required", domain.ErrEmptySubject)
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
		return 0, domain.NewError(domain.ReasonInternalError, "pap", "pap: failed to bump epoch", err)
	}

	// 감사 이벤트 기록
	if s.audit != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   fmt.Sprintf("pap-epoch-%s-%d", cleanSub, newEpoch),
			Step:      "pap.bump_epoch",
			Actor:     "admin",
			Action:    "epoch.bump",
			Success:   true,
			Metadata: map[string]interface{}{
				"subject":        cleanSub,
				"previous_epoch": int64(prevEpoch),
				"new_epoch":      int64(newEpoch),
			},
		}
		if err := s.audit.Log(auditEv); err != nil {
			return 0, domain.NewError(domain.ReasonAuditLogFailed, "pap", "pap: audit logging failed", err)
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
