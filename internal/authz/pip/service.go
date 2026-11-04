package pip

import (
	"context"
	"fmt"
	"strings"

	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// SubjectSnapshot 은 domain.SubjectSnapshot 의 별칭이다(DIP: 정의는 도메인에 있다).
type SubjectSnapshot = domain.SubjectSnapshot

// Service 는 정책 정보점(PIP)의 읽기 전용 조회 규약이다.
type Service interface {
	// GetSubjectSnapshot 은 PDP가 단일 트랜잭션에서 결정할 수 있도록 주체의 최신 Epoch와 활성 Grant 목록을 원자적으로 읽어 반환한다.
	GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)

	// GetActiveGrants 는 특정 주체의 활성화(active)된 Grant 목록만 반환한다.
	GetActiveGrants(ctx context.Context, subject string) ([]domain.Grant, error)

	// GetCurrentEpoch 는 특정 주체의 현재 Security Epoch를 반환한다 (미등록 주체는 기본값 1).
	GetCurrentEpoch(ctx context.Context, subject string) (domain.Epoch, error)
}

// pipService 는 PIP Service의 기본 구현체다.
type pipService struct {
	store state.Store
	clock domain.Clock
}

// Option 은 PIP 서비스 생성 옵션이다.
type Option func(*pipService)

// WithClock 은 스냅샷 시각에 쓸 시계를 주입한다 (미주입 시 RealClock).
func WithClock(c domain.Clock) Option {
	return func(s *pipService) {
		if c != nil {
			s.clock = c
		}
	}
}

// NewService 는 PIP 서비스를 생성한다.
func NewService(store state.Store, opts ...Option) Service {
	s := &pipService{
		store: store,
		clock: domain.RealClock{},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// GetSubjectSnapshot 은 대상 주체의 현재 Epoch 및 활성 Grant 목록을 읽어 스냅샷으로 반환한다.
func (s *pipService) GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error) {
	cleanSub := strings.TrimSpace(subject)
	if cleanSub == "" {
		return nil, domain.ErrEmptySubject
	}

	st, err := s.store.Load()
	if err != nil {
		return nil, fmt.Errorf("pip: failed to load state: %w", err)
	}

	epoch := st.Epochs.Get(cleanSub)
	epochsCopy := make(domain.SecurityEpochs, len(st.Epochs))
	for k, v := range st.Epochs {
		epochsCopy[k] = v
	}
	activeGrants := make([]domain.Grant, 0)
	revokedGrants := make([]domain.Grant, 0)

	for _, g := range st.Grants {
		if g.Subject == cleanSub {
			if g.IsActive() {
				activeGrants = append(activeGrants, g)
			} else if g.Status == domain.GrantStatusRevoked {
				revokedGrants = append(revokedGrants, g)
			}
		}
	}

	var approvals []domain.Approval
	for _, a := range st.Approvals {
		if a.Subject == cleanSub {
			approvals = append(approvals, a)
		}
	}

	return &SubjectSnapshot{
		Approvals:     approvals,
		Subject:       cleanSub,
		CurrentEpoch:  epoch,
		ActiveGrants:  activeGrants,
		RevokedGrants: revokedGrants,
		SubjectEpochs: epochsCopy,
		Timestamp:     s.clock.Now().UTC(),
	}, nil
}

// GetActiveGrants 는 특정 주체의 활성 Grant 목록만 반환한다.
func (s *pipService) GetActiveGrants(ctx context.Context, subject string) ([]domain.Grant, error) {
	snapshot, err := s.GetSubjectSnapshot(ctx, subject)
	if err != nil {
		return nil, err
	}
	return snapshot.ActiveGrants, nil
}

// GetCurrentEpoch 는 특정 주체의 Security Epoch를 반환한다.
func (s *pipService) GetCurrentEpoch(ctx context.Context, subject string) (domain.Epoch, error) {
	cleanSub := strings.TrimSpace(subject)
	if cleanSub == "" {
		return 0, domain.ErrEmptySubject
	}

	st, err := s.store.Load()
	if err != nil {
		return 0, fmt.Errorf("pip: failed to load state: %w", err)
	}

	return st.Epochs.Get(cleanSub), nil
}
