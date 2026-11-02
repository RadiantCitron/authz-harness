package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/mcp"
)

type dummyMCPExecutor struct{}

func (d *dummyMCPExecutor) ExecuteTool(ctx context.Context, req *mcp.ToolCallRequest) (*mcp.ToolExecutionResult, error) {
	return &mcp.ToolExecutionResult{
		Content: []mcp.ToolContent{
			{Type: "text", Text: "dummy output"},
		},
	}, nil
}

func TestMCPRunner_ServePipe(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"
	in := strings.NewReader(input)
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	runner := NewMCPRunner(in, out, errOut, &dummyMCPExecutor{})
	code := runner.Run(context.Background(), []string{"serve"})

	if code != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess(0), got %v (stderr: %s)", code, errOut.String())
	}

	if !strings.Contains(out.String(), `"protocolVersion":"2024-11-05"`) {
		t.Errorf("expected initialize response in stdout, got: %s", out.String())
	}
}

func TestMCPRunner_InvalidCommand(t *testing.T) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	runner := NewMCPRunner(nil, out, errOut, nil)
	code := runner.Run(context.Background(), []string{"unknown"})

	if code != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput(14), got %v", code)
	}
}
