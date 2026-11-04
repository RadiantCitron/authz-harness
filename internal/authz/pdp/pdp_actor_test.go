package pdp_test

import (
	"strings"
	"testing"
	"time"

	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/domain"
)

// TestEvaluate_ActorChainEpoch 는 TC-040-03~05: act 사슬 모든 고리를 현재 Epoch 와 동등 비교한다.
func TestEvaluate_ActorChainEpoch(t *testing.T) {
	grant := domain.Grant{ID: "g1", Subject: "worker-01", Action: domain.ActionFileRead, Resource: "a.txt",
		Status: domain.GrantStatusActive, CreatedAt: time.Now().UTC()}
	snap := func(epochs domain.SecurityEpochs) *pip.SubjectSnapshot {
		return &pip.SubjectSnapshot{Subject: "worker-01", CurrentEpoch: 1,
			ActiveGrants: []domain.Grant{grant}, SubjectEpochs: epochs}
	}
	chain := func(lead, mid domain.Epoch) *domain.ActorClaim {
		return &domain.ActorClaim{Subject: "mid-01", Epoch: mid,
			Actor: &domain.ActorClaim{Subject: "lead-01", Epoch: lead}}
	}

	cases := []struct {
		name       string
		actor      *domain.ActorClaim
		snapshot   *pip.SubjectSnapshot
		want       pdp.DecisionType
		wantReason domain.Reason
		detailHas  string
	}{
		{"TC-040-05 모든 고리 일치는 ALLOW", chain(1, 1), snap(domain.SecurityEpochs{"lead-01": 1, "mid-01": 1}), pdp.DecisionAllow, domain.ReasonAuthorized, ""},
		{"act 없는 토큰은 SubjectEpochs 없이도 ALLOW", nil, snap(nil), pdp.DecisionAllow, domain.ReasonAuthorized, ""},
		{"최상위 조상 Epoch 증가는 거부", chain(1, 1), snap(domain.SecurityEpochs{"lead-01": 2, "mid-01": 1}), pdp.DecisionDeny, domain.ReasonSubjectEpochRevoked, "lead-01"},
		{"중간 조상 Epoch 증가는 거부", chain(1, 1), snap(domain.SecurityEpochs{"lead-01": 1, "mid-01": 2}), pdp.DecisionDeny, domain.ReasonSubjectEpochRevoked, "mid-01"},
		{"조상 제시 Epoch 가 현재보다 크면(이상 비교 우회) 거부", chain(3, 1), snap(domain.SecurityEpochs{"lead-01": 2, "mid-01": 1}), pdp.DecisionDeny, domain.ReasonSubjectEpochRevoked, "lead-01"},
		{"TC-040-03 고리 Epoch 0은 건너뛰지 않고 거부", chain(0, 1), snap(domain.SecurityEpochs{"lead-01": 1, "mid-01": 1}), pdp.DecisionDeny, domain.ReasonSubjectEpochRevoked, "lead-01"},
		{"TC-040-04 act 가 있는데 SubjectEpochs nil 은 거부", chain(1, 1), snap(nil), pdp.DecisionDeny, domain.ReasonSubjectEpochRevoked, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := pdp.Evaluate(pdp.Request{Subject: "worker-01", Action: domain.ActionFileRead, Resource: "a.txt",
				Epoch: 1, Actor: tc.actor}, tc.snapshot)
			if d.Decision != tc.want || d.Reason != tc.wantReason {
				t.Fatalf("got %s/%s, want %s/%s (%s)", d.Decision, d.Reason, tc.want, tc.wantReason, d.Details)
			}
			if tc.detailHas != "" && !strings.Contains(d.Details, tc.detailHas) {
				t.Errorf("details %q lacks %q", d.Details, tc.detailHas)
			}
		})
	}
}
