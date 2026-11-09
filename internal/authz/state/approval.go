// Package state 는 사람 승인(Approval)의 1회성 등록, 만료 정리(Prune), 원자적 소비(Consume) 로직을 제공한다.
//
// [승인 생애주기 및 동시성 원칙]
// 1. 1회성 소비(One-Time Consumption):
//   - 사람이 승인한 위험 작업은 단 1회만 실행될 수 있어야 한다.
//   - ConsumeApproval 은 매칭되는 승인을 검증한 후 즉시 원장 슬라이스에서 삭제(Delete-on-Use)한다.
//
// 2. 만료 승인 자동 회수 (pruneExpired):
//   - CreateApproval 및 ConsumeApproval 호출 시마다 현재 시각 기준으로 만료(now >= ExpiresAt)된 승인을 메모리 슬라이스 필터링으로 자동 제거한다.
//
// 3. 배타적 락 기반 단일 소비 보장:
//   - 다중 프로세스가 동일한 승인 ID 를 동시에 소비하려 경합할 때, flock 배타적 락을 통해 먼저 락을 획득한 1개 프로세스만 성공하고 후속 프로세스는 "approval not found or already consumed" 로 안전하게 거부된다.
package state

import (
	"fmt"
	"time"

	"authz-harness/internal/domain"
)

// pruneExpired 는 now >= ExpiresAt 인 만료된 승인을 슬라이스에서 필터링하여 지운다.
// Go 슬라이스 재사용 idiom (st.Approvals[:0]) 을 사용하여 불필요한 메모리 할당을 줄인다.
func pruneExpired(st *GrantsState, now time.Time) {
	kept := st.Approvals[:0]
	for _, a := range st.Approvals {
		if now.Before(a.ExpiresAt) {
			kept = append(kept, a)
		}
	}
	st.Approvals = kept
}

// CreateApproval 은 만료분을 정리하고 신규 승인을 저장소에 원자적으로 추가한다.
// 동일한 Approval ID 가 이미 존재하면 중복 오류를 반환한다.
func CreateApproval(s Store, a domain.Approval, now time.Time) error {
	return s.Update(func(st *GrantsState) error {
		pruneExpired(st, now)
		for _, e := range st.Approvals {
			if e.ID == a.ID {
				return domain.NewError(domain.ReasonInternalError, fmt.Sprintf("approval id %s already exists", a.ID), nil)
			}
		}
		st.Approvals = append(st.Approvals, a)
		return nil
	})
}

// ConsumeApproval 은 승인을 ID 로 찾아 재검증한 뒤 지운다 (1회성 = 삭제).
// 검증이 실패해도 만료 정리는 저장된다. 두 프로세스가 같은 ID 를 동시에 소비해도 flock 직렬화로 1건만 성공한다.
func ConsumeApproval(s Store, id string, b domain.ApprovalBinding, now time.Time) error {
	var outcome error
	err := s.Update(func(st *GrantsState) error {
		pruneExpired(st, now)
		idx := -1
		for i, a := range st.Approvals {
			if a.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			outcome = domain.NewError(domain.ReasonApprovalRequired, "approval not found or already consumed", nil)
			return nil
		}
		if r := st.Approvals[idx].Matches(b, now); r != domain.ReasonAuthorized {
			outcome = domain.NewError(r, "approval does not match request", nil)
			return nil
		}
		st.Approvals = append(st.Approvals[:idx], st.Approvals[idx+1:]...)
		return nil
	})
	if err != nil {
		return err
	}
	return outcome
}

// ApprovalConsumer 는 Store 위에서 승인을 소비하는 PEP 포트(domain.ApprovalConsumer) 구현체다.
type ApprovalConsumer struct {
	store Store
}

// NewApprovalConsumer 는 Store 를 주입받아 ApprovalConsumer 인스턴스를 생성한다.
func NewApprovalConsumer(s Store) *ApprovalConsumer {
	return &ApprovalConsumer{store: s}
}

// ConsumeApproval 은 state.ConsumeApproval 에 위임하여 원자적 승인 소비를 수행한다.
func (c *ApprovalConsumer) ConsumeApproval(id string, b domain.ApprovalBinding, now time.Time) error {
	return ConsumeApproval(c.store, id, b, now)
}
