package exchange_test

import (
	"testing"

	"authz-harness/internal/domain"
)

// 거부 감사의 Stage 는 실패 단계, 성공 감사의 Stage 는 마지막 통과 단계다.
func TestExchange_AuditStageField(t *testing.T) { // TC-080-06·07
	want := map[string]struct {
		action string
		stage  domain.Stage
	}{
		"client_auth":             {"token.exchange.deny", domain.StageClientAuth},
		"subject_empty":           {"token.exchange.deny", domain.StageDelegationSubject},
		"subject_not_allowed":     {"token.exchange.deny", domain.StageDelegationSubject},
		"parent_token":            {"token.exchange.deny", domain.StageParentToken},
		"lineage_snapshot_error":  {"token.exchange.deny", domain.StageLineageEpoch},
		"lineage_epoch_mismatch":  {"token.exchange.deny", domain.StageLineageEpoch},
		"downscope":               {"token.exchange.deny", domain.StageDownscope},
		"budget_downscope_static": {"token.exchange.deny", domain.StageBudgetDownscope},
		"budget_no_ledger":        {"token.exchange.deny", domain.StageBudgetDownscope},
		"budget_reserve_fail":     {"token.exchange.deny", domain.StageBudgetReserve},
		"token_issue_fail":        {"token.exchange.deny", domain.StageTokenIssue},
		"success_plain":           {"token.exchanged", domain.StageTokenIssue},
		"success_budget":          {"token.exchanged", domain.StageBudgetReserve},
	}
	for name, mk := range snapCases() {
		w, ok := want[name]
		if !ok {
			t.Fatalf("no expectation for %s", name)
		}
		e := mk(t)
		var last map[string]interface{}
		for _, ev := range rawEvents(t, e.auditP) {
			if ev["action"] == w.action {
				last = ev
			}
		}
		if last == nil {
			t.Fatalf("%s: no %s event", name, w.action)
		}
		if last["stage"] != string(w.stage) {
			t.Errorf("%s: stage=%v want %s", name, last["stage"], w.stage)
		}
	}
}

// TC-080-05: 예약 실패(E2E-50 형태)는 자식 토큰을 돌려주지 않고 부모 잔여를 바꾸지 않는다.
func TestExchange_ReserveFailureKeepsParentRemaining(t *testing.T) {
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 5})
	if _, err := e.exch(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 2}); err != nil {
		t.Fatal(err)
	}
	res, err := e.exch(r.TokenString, "worker-02", &domain.Budget{MaxCalls: 4})
	reasonOf(t, err, domain.ReasonDelegationBudgetExceeded, 12)
	if res != nil {
		t.Fatal("no child token")
	}
	if remaining(t, e.ledger, r.Claims.JWTID) != 3 {
		t.Fatal("parent remaining must stay 3")
	}
}

func TestExchange_ReserveFailureIsBudgetReserveStage(t *testing.T) {
	e := newBudgetEnv(t, true, true)
	r := e.root(t, &domain.Budget{MaxCalls: 5})
	_, _ = e.exch(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 2})
	_, _ = e.exch(r.TokenString, "worker-02", &domain.Budget{MaxCalls: 4})
	var last map[string]interface{}
	for _, ev := range rawEvents(t, e.auditP) {
		if ev["action"] == "token.exchange.deny" {
			last = ev
		}
	}
	if last == nil || last["stage"] != string(domain.StageBudgetReserve) {
		t.Fatalf("got %v", last)
	}
}
