// Package domain 은 순수 인가 판단 두뇌(PDP)에 주입되는 주체별 권한 상태 스냅샷 및 계보 Epoch 검증 로직을 제공한다.
//
// [순수 함수 두뇌(PDP)와 스냅샷 주입 아키텍처]
// 1. I/O 가 배제된 순수 인가 판단:
//    - PDP(authz/pdp)는 디스크를 읽거나 네트워크를 호출하지 않는다.
//    - 정책 정보점(authz/pip)이 디스크 상태 저장소에서 읽어온 불변 스냅샷(SubjectSnapshot)을 PDP.Evaluate 에 인자로 넘겨주며,
//      PDP 는 오직 메모리 상의 스냅샷 데이터와 클레임만을 대조하여 허용/거부/승인필요를 수학적으로 판정한다.
// 2. 위임 계보(ActorClaim) 연쇄 Epoch 검증:
//    - ValidateLineageEpoch 는 주체 본인뿐만 아니라 act 사슬에 연결된 모든 조상의 Epoch 를 한 번의 순회로 검증하여
//      퇴사자나 권한 회수된 상위 에이전트의 하위 토큰 오용을 원천 봉쇄한다.
package domain

import (
	"context"
	"time"
)

// SubjectSnapshot 은 PDP 인가 결정을 위해 공급되는 특정 주체의 권한 상태 스냅샷이다.
// 동시성 경합을 배제하기 위해 한 번 로드된 스냅샷은 불변(Immutable)으로 취급된다.
type SubjectSnapshot struct {
	// Subject 는 스냅샷의 대상 주체 식별자다 (예: "worker-01").
	Subject string `json:"subject"`

	// CurrentEpoch 는 현재 시점 주체의 활성 보안 세대 번호다.
	CurrentEpoch Epoch `json:"current_epoch"`

	// ActiveGrants 는 주체에게 부여된 활성 권한 목록이다.
	ActiveGrants []Grant `json:"active_grants"`

	// RevokedGrants 는 주체에게서 회수된 권한 목록이다.
	RevokedGrants []Grant `json:"revoked_grants,omitempty"`

	// Timestamp 는 스냅샷이 생성(로드)된 시각이다.
	Timestamp time.Time `json:"timestamp"`

	// SubjectEpochs 는 모든 주체의 현재 Epoch 사본 맵이다 (위임 계보 연쇄 회수 검사용).
	// 호출자가 원본을 오염시키지 못하도록 방어적으로 복사되어 공급된다.
	SubjectEpochs SecurityEpochs `json:"subject_epochs,omitempty"`

	// Approvals 는 이 주체에 대해 발행된 유효 승인 티켓 사본 목록이다.
	Approvals []Approval `json:"approvals,omitempty"`
}

// ValidateLineageEpoch 는 주체 본인(sub, currentEpoch)과 조상 위임 사슬(act)의 Epoch 를 검증하는 순수 함수다.
//
// [검증 흐름]:
// 1. 주체 본인 Epoch 검증: 제시된 토큰의 currentEpoch 가 스냅샷의 CurrentEpoch 와 다르면 즉시 ReasonSubjectEpochRevoked 반환.
// 2. 조상 위임 사슬(act) 연쇄 검증:
//    - act 포인터를 따라 조상(Parent -> GrandParent...)을 순회하며,
//      각 조상의 제시 Epoch 가 s.SubjectEpochs 에 기록된 조상의 현재 Epoch 와 일치하는지 대조.
//    - 어느 하나라도 불일치하면 ReasonSubjectEpochRevoked 와 불일치한 조상 ActorClaim 을 반환.
// 3. 모두 일치하면 ("", nil) 을 반환하여 정상 통과를 알린다.
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

// SnapshotProvider 는 PDP 및 Token Exchange 가 주체 상태 스냅샷을 조회하는 도메인 포트 인터페이스(DIP)다.
// internal/authz/pip.Service 가 이 인터페이스를 구현하여 제공한다.
type SnapshotProvider interface {
	GetSubjectSnapshot(ctx context.Context, subject string) (*SubjectSnapshot, error)
}
