package state

import (
	"fmt"
	"time"

	"authz-harness/internal/domain"
)

const stageApprovalStore = "approval_store"

// pruneExpired 는 now >= ExpiresAt 인 승인을 지운다.
func pruneExpired(st *GrantsState, now time.Time) {
	kept := st.Approvals[:0]
	for _, a := range st.Approvals {
		if now.Before(a.ExpiresAt) {
			kept = append(kept, a)
		}
	}
	st.Approvals = kept
}

// CreateApproval 은 만료분을 정리하고 새 승인을 붙인다. 같은 ID 가 있으면 오류(16)다.
func CreateApproval(s Store, a domain.Approval, now time.Time) error {
	return s.Update(func(st *GrantsState) error {
		pruneExpired(st, now)
		for _, e := range st.Approvals {
			if e.ID == a.ID {
				return domain.NewError(domain.ReasonInternalError, stageApprovalStore, fmt.Sprintf("approval id %s already exists", a.ID), nil)
			}
		}
		st.Approvals = append(st.Approvals, a)
		return nil
	})
}

// ConsumeApproval 은 승인을 ID 로 찾아 재검증한 뒤 지운다(1회성 = 삭제).
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
			outcome = domain.NewError(domain.ReasonApprovalRequired, stageApprovalStore, "approval not found or already consumed", nil)
			return nil
		}
		if r := st.Approvals[idx].Matches(b, now); r != domain.ReasonAuthorized {
			outcome = domain.NewError(r, stageApprovalStore, "approval does not match request", nil)
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

// ApprovalConsumer 는 Store 위에서 승인을 소비하는 PEP 포트(040) 구현이다.
type ApprovalConsumer struct{ store Store }

// NewApprovalConsumer 는 승인 소비기를 만든다.
func NewApprovalConsumer(s Store) *ApprovalConsumer { return &ApprovalConsumer{store: s} }

// ConsumeApproval 은 state.ConsumeApproval 에 위임한다.
func (c *ApprovalConsumer) ConsumeApproval(id string, b domain.ApprovalBinding, now time.Time) error {
	return ConsumeApproval(c.store, id, b, now)
}
