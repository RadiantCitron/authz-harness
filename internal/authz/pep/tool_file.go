package pep

import (
	"context"
	"fmt"

	"authz-harness/internal/domain"
	"authz-harness/internal/jail"
)

func resolveInJail(c *Call, forWrite bool) error {
	safePath, jailErr := c.cfg.Jail.ResolvePath(c.st.resource, forWrite)
	if jailErr != nil {
		return domain.NewError(jail.ReasonFromError(jailErr), fmt.Sprintf("Gate 2c jail path containment violated: %v", jailErr), jailErr)
	}
	c.st.safePath = safePath
	return nil
}

type fileReadTool struct{}

func (fileReadTool) Prepare(*Call) error         { return nil }
func (fileReadTool) CheckBoundary(c *Call) error { return resolveInJail(c, false) }
func (fileReadTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{PostCharge: true, RefundAfterStart: true}
}
func (fileReadTool) Execute(_ context.Context, c *Call) (Output, error) {
	data, err := c.cfg.Jail.ReadFile(c.st.resource)
	if err != nil {
		return Output{}, domain.NewError(domain.ReasonInternalError, fmt.Sprintf("pep: failed to read file in jail: %v", err), err)
	}
	return Output{Data: data, BytesRead: len(data)}, nil
}

type fileWriteTool struct{}

func (fileWriteTool) Prepare(*Call) error         { return nil }
func (fileWriteTool) CheckBoundary(c *Call) error { return resolveInJail(c, true) }
func (fileWriteTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{ChargeWriteBytes: true, RefundAfterStart: true}
}
func (fileWriteTool) Execute(_ context.Context, c *Call) (Output, error) {
	if err := c.cfg.Jail.WriteFile(c.st.resource, c.req.Data); err != nil {
		return Output{}, domain.NewError(domain.ReasonInternalError, fmt.Sprintf("pep: failed to write file in jail: %v", err), err)
	}
	return Output{BytesWrote: len(c.req.Data)}, nil
}
