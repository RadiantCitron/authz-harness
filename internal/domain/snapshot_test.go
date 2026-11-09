package domain_test

import (
	"testing"

	"authz-harness/internal/domain"
)

// 계획 032 L1: 3단 위임 사슬에서 가운데 조상만 불일치할 때 ValidateLineageEpoch가 그 조상을 반환한다.
func TestValidateLineageEpoch_L1(t *testing.T) {
	// 위임 사슬: worker-01 -> mid-01 (Epoch 1) -> root-01 (Epoch 2)
	// root-01의 현재 Epoch는 2로 일치하지만, mid-01의 현재 Epoch는 3으로 불일치
	chain := &domain.ActorClaim{
		Subject: "mid-01",
		Epoch:   1,
		Actor: &domain.ActorClaim{
			Subject: "root-01",
			Epoch:   2,
		},
	}

	snap := &domain.SubjectSnapshot{
		Subject:      "worker-01",
		CurrentEpoch: 1,
		SubjectEpochs: domain.SecurityEpochs{
			"mid-01":  3, // 불일치
			"root-01": 2, // 일치
		},
	}

	reason, mismatch := snap.ValidateLineageEpoch("worker-01", 1, chain)
	if reason != domain.ReasonSubjectEpochRevoked {
		t.Fatalf("expected ReasonSubjectEpochRevoked, got %q", reason)
	}
	if mismatch == nil || mismatch.Subject != "mid-01" || mismatch.Epoch != 1 {
		t.Fatalf("expected mismatch to be mid-01 (epoch 1), got %+v", mismatch)
	}

	// 주체 본인 불일치 케이스: mismatch == nil
	snapWrongSub := &domain.SubjectSnapshot{
		Subject:      "worker-01",
		CurrentEpoch: 2, // 불일치 (제시 1)
	}
	reason, mismatch = snapWrongSub.ValidateLineageEpoch("worker-01", 1, nil)
	if reason != domain.ReasonSubjectEpochRevoked {
		t.Fatalf("expected ReasonSubjectEpochRevoked, got %q", reason)
	}
	if mismatch != nil {
		t.Fatalf("expected nil mismatch on subject mismatch, got %+v", mismatch)
	}

	// 정상 케이스
	snapOk := &domain.SubjectSnapshot{
		Subject:      "worker-01",
		CurrentEpoch: 1,
		SubjectEpochs: domain.SecurityEpochs{
			"mid-01":  1,
			"root-01": 2,
		},
	}
	reason, mismatch = snapOk.ValidateLineageEpoch("worker-01", 1, chain)
	if reason != "" || mismatch != nil {
		t.Fatalf("expected valid lineage, got reason=%q mismatch=%+v", reason, mismatch)
	}
}
