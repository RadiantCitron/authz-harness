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

// SnapshotProvider 는 PDP가 주체 상태 스냅샷을 조회하는 도메인 포트(DIP)다.
type SnapshotProvider interface {
	GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)
}
