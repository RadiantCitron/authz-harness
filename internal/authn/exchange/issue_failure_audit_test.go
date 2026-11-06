package exchange_test

import (
	"context"
	"errors"
	"testing"

	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

type noActiveKey struct{ keys.KeyManager }

func (noActiveKey) GetActiveSigningKey() (*domain.SigningKey, error) {
	return nil, errors.New("no active key")
}

// 계획 017 T8 — 교환 안에서 실제 발급기가 실패해도 교환 결과(사유·종료 코드·거부 감사 1건)는 그대로여야 한다.
// 자식 발급기의 token.issue.deny 가 같은 TraceID 에 추가되는 것은 허용되지만 최대 1건이다.
func TestExchange_T8_ChildIssueFailureKeepsExchangeOutcome(t *testing.T) {
	e := newBudgetEnv(t, false, false)
	parent := e.root(t, nil).TokenString
	issuer := token.NewService(noActiveKey{}, token.NewInMemoryClientRegistry(), e.aw, e.clk)
	svc := exchange.NewExchangeService(issuer, e.verifier, token.NewInMemoryClientRegistry(), nil, e.aw, e.clk)
	trace := domain.AuditContext{TraceID: "trace-t8", Actor: "t8"}

	res, err := svc.Exchange(context.Background(), exReq(parent, "worker-01", nil), trace)
	if res != nil || err == nil {
		t.Fatalf("must be denied: %v %v", res, err)
	}
	reason, code := domain.ReasonFromError(err, ""), domain.ExitCodeFromError(err, 0)
	t.Logf("baseline exchange outcome: reason=%s exit=%d", reason, code)

	var exDeny, issueDeny int
	for _, ev := range rawEvents(t, e.auditP) {
		if ev["trace_id"] != "trace-t8" {
			continue
		}
		switch ev["action"] {
		case "token.exchange.deny":
			exDeny++
			if ev["stage"] != string(domain.StageTokenIssue) {
				t.Errorf("exchange deny stage=%v", ev["stage"])
			}
		case "token.issue.deny":
			issueDeny++
		}
	}
	if exDeny != 1 {
		t.Errorf("want exactly 1 token.exchange.deny, got %d", exDeny)
	}
	if issueDeny > 1 {
		t.Errorf("child issue deny must be at most 1, got %d", issueDeny)
	}
	t.Logf("baseline token.issue.deny in exchange trace: %d", issueDeny)
}
