package pap_test

import (
	"context"
	"testing"

	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
)

// 계획 020 V1: 정식 액션이 아닌 문자열로는 승인을 만들 수 없고, 원장은 바뀌지 않는다.
func TestCreateApproval_RejectsUnknownAction(t *testing.T) {
	svc, statePath, _ := setupTestPAP(t)
	for _, act := range []domain.Action{"file:delete", "typo"} {
		_, err := svc.CreateApproval(context.Background(), pap.CreateApprovalRequest{
			Subject: "w", Action: act, Resource: "s.txt", TokenJTI: "j1",
		})
		if err == nil {
			t.Fatalf("action %q: approval must be rejected", act)
		}
		if got := domain.ReasonFromError(err, ""); got != domain.ReasonInvalidArguments {
			t.Errorf("action %q: reason = %q, want %q", act, got, domain.ReasonInvalidArguments)
		}
	}
	st, err := mustStore(t, statePath).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Approvals) != 0 {
		t.Fatalf("ledger must be unchanged, got %d approvals", len(st.Approvals))
	}
}
