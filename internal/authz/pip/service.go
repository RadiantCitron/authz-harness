// Package pip 는 정책 정보점(Policy Information Point)으로서 인가 판정에 필요한 주체의 상태 스냅샷을 원자적으로 공급한다.
//
// [DIP 및 아키텍처 원칙]
// 1. 도메인 모델 의존 (Domain SSOT):
//   - SubjectSnapshot 정의는 internal/domain 패키지에 위치하며, pip 는 타입 별칭(type SubjectSnapshot = domain.SubjectSnapshot)으로 참조한다.
//   - PDP 는 PIP 구체 구현체가 아닌 domain.SnapshotProvider 인터페이스에 의존한다.
//
// 2. 방어적 복사 (Defensive Copy):
//   - 상태 저장소(state.Store)로부터 로드한 SecurityEpochs 맵을 신규 맵(epochsCopy)으로 복사하여 반환함으로써,
//     스냅샷을 수신한 PDP 나 교환 파이프라인의 조작이 내부 저장소 캐시에 영향을 미치지 않도록 불변성을 보장한다.
//
// 3. 단일 트랜잭션 일관성:
//   - 주체의 현재 Epoch, 활성/회수된 Grant 목록, 유효한 사람 승인(Approval) 목록을 한 시점의 일관된 스냅샷으로 묶어 제공한다.
package pip

import (
	"context"
	"fmt"
	"strings"

	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// SubjectSnapshot 은 domain.SubjectSnapshot 의 별칭이다 (DIP: 정의는 도메인에 있다).
type SubjectSnapshot = domain.SubjectSnapshot

// Service 는 정책 정보점(PIP)의 읽기 전용 조회 DIP 규약이다.
type Service interface {
	// GetSubjectSnapshot 은 PDP가 단일 트랜잭션에서 결정할 수 있도록 주체의 최신 Epoch와 활성 Grant 목록을 원자적으로 읽어 반환한다.
	GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)
}

// pipService 는 PIP Service의 기본 구현체다.
type pipService struct {
	store state.Store
	clock domain.Clock
}

// Option 은 PIP 서비스 생성을 위한 함수형 옵션(Functional Option)이다.
type Option func(*pipService)

// WithClock 은 스냅샷 시각에 쓸 시계를 주입한다 (미주입 시 RealClock).
func WithClock(c domain.Clock) Option {
	return func(s *pipService) {
		if c != nil {
			s.clock = c
		}
	}
}

// NewService 는 state.Store 를 기반으로 PIP 서비스를 생성한다.
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

// GetSubjectSnapshot 은 대상 주체의 현재 Epoch, 활성 Grant, 회수된 Grant, 사람 승인 목록을 읽어 스냅샷으로 반환한다.
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
	// 방어적 복사: 내부 맵 오염 방지
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
