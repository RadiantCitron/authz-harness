package pep

import (
	"context"
	"fmt"

	"authz-harness/internal/domain"
	"authz-harness/internal/execguard"
)

type execRunTool struct{}

func (execRunTool) Prepare(*Call) error { return nil }

func (execRunTool) CheckBoundary(c *Call) error {
	if c.cfg.ExecRunner == nil {
		return domain.NewError(domain.ReasonInternalError, string(domain.StageBoundary), "exec runner is not configured (fail-closed)", nil)
	}
	if err := execguard.Validate(c.st.resource, string(c.req.Data)); err != nil {
		return domain.NewError(domain.ReasonFromError(err, domain.ReasonExecNotAllowed), string(domain.StageBoundary), fmt.Sprintf("Gate 2c exec rejected: %v", err), err)
	}
	return nil
}

// 실행이 시작되면 실패해도 환급하지 않는다(부작용이 이미 났을 수 있다).
func (execRunTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{ChargeWriteBytes: true, PostCharge: true, RefundAfterStart: false}
}

func (execRunTool) Execute(ctx context.Context, c *Call) (Output, error) {
	out, err := c.cfg.ExecRunner.Run(ctx, c.st.resource, string(c.req.Data))
	if err != nil {
		return Output{}, domain.NewError(domain.ReasonFromError(err, domain.ReasonInternalError), string(domain.StageExecute), fmt.Sprintf("pep: exec failed: %v", err), err)
	}
	return Output{Data: out, BytesRead: len(out)}, nil
}
