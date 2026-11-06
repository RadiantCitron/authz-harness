package pep

import (
	"context"
	"fmt"

	"authz-harness/internal/domain"
	"authz-harness/internal/netguard"
)

type netFetchTool struct{}

func (netFetchTool) Prepare(c *Call) error {
	if len(c.req.Data) > 0 {
		return domain.NewError(domain.ReasonInvalidArguments, "net:fetch must not carry data", nil)
	}
	t, err := netguard.ParseTarget(c.st.resource)
	if err != nil {
		// 원문 URL(자격 정보·질의 포함 가능)이 감사에 남지 않게 지문만 기록한다.
		c.st.argHash = domain.DataDigest([]byte(c.st.resource))
		c.st.resource = "<invalid-url>"
		return domain.NewError(domain.ReasonEgressDenied, "net:fetch target rejected", err)
	}
	c.st.resource = t.HostPort
	c.fetchTarget = t
	c.st.argHash = domain.DataDigest([]byte(t.URL))
	return nil
}

func (netFetchTool) CheckBoundary(c *Call) error {
	if c.cfg.NetGuard == nil {
		return domain.NewError(domain.ReasonInternalError, "net guard is not configured (fail-closed)", nil)
	}
	if err := c.cfg.NetGuard.Check(c.st.resource); err != nil {
		return domain.NewError(domain.ReasonFromError(err, domain.ReasonEgressDenied), fmt.Sprintf("Gate 2c egress denied: %v", err), err)
	}
	return nil
}

func (netFetchTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{PostCharge: true, RefundAfterStart: true}
}

func (netFetchTool) Execute(ctx context.Context, c *Call) (Output, error) {
	data, err := c.cfg.NetGuard.Fetch(ctx, c.fetchTarget)
	if err != nil {
		return Output{}, domain.NewError(domain.ReasonFromError(err, domain.ReasonInternalError), fmt.Sprintf("pep: net fetch failed: %v", err), err)
	}
	return Output{Data: data, BytesRead: len(data)}, nil
}
