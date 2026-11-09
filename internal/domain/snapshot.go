package domain

import (
	"context"
	"time"
)

// SubjectSnapshot 은 PDP 인가 결정을 위해 공급되는 주체별 권한 상태 스냅샷이다.
type SubjectSnapshot struct {
	Subject       string    `json:"subject"`
	CurrentEpoch  Epoch     `json:"current_epoch"`
	ActiveGrants  []Grant   `json:"active_grants"`
	RevokedGrants []Grant   `json:"revoked_grants,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	// SubjectEpochs 는 모든 주체의 현재 Epoch 사본이다(위임 계보 연쇄 회수 검사용, 호출자가 원본을 바꾸지 못하도록 복사).
	SubjectEpochs SecurityEpochs `json:"subject_epochs,omitempty"`
	// Approvals 는 이 주체의 승인 사본이다(같은 Load 에서 공급, 호출자가 원장을 바꾸지 못하도록 복사).
	Approvals []Approval `json:"approvals,omitempty"`
}

// ValidateLineageEpoch 는 주체 본인(sub, currentEpoch)과 조상 위임 사슬(act)의 Epoch 를 검증한다.
// 본인 또는 조상의 제시 Epoch 가 현재 활성 Epoch 와 일치하지 않으면 ReasonSubjectEpochRevoked 와
// 불일치한 조상 ActorClaim(조상 불일치 시, 본인 불일치 또는 정보 누락 시 nil)을 반환한다.
// 모두 정상이면 ("", nil)을 반환한다.
func (s *SubjectSnapshot) ValidateLineageEpoch(sub string, currentEpoch Epoch, act *ActorClaim) (Reason, *ActorClaim) {
	if s == nil {
		return ReasonNoActiveGrant, nil
	}
	// 1. 주체 본인 Epoch 검증
	epoch := Epoch(currentEpoch)
	if epoch < 1 {
		epoch = 1
	}
	if epoch != s.CurrentEpoch {
		return ReasonSubjectEpochRevoked, nil
	}

	// 2. 위임 조상 사슬(act) 연쇄 검증
	if act != nil {
		if s.SubjectEpochs == nil {
			return ReasonSubjectEpochRevoked, nil
		}
		for a := act; a != nil; a = a.Actor {
			if a.Epoch < 1 || s.SubjectEpochs.Get(a.Subject) != a.Epoch {
				return ReasonSubjectEpochRevoked, a
			}
		}
	}
	return "", nil
}

// SnapshotProvider 는 PDP가 주체 상태 스냅샷을 조회하는 도메인 포트(DIP)다.
type SnapshotProvider interface {
	GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)
}
