package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
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

	runner := NewMCPRunner(in, out, errOut, "", "", "", "", "", &dummyMCPExecutor{})
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

	runner := NewMCPRunner(nil, out, errOut, "", "", "", "", "", nil)
	code := runner.Run(context.Background(), []string{"unknown"})

	if code != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput(14), got %v", code)
	}
}

// 로드맵 16 / 050 TC-050-04
func TestMCPWorkerArgs_NetAllowPassthrough(t *testing.T) {
	with := mcpWorkerArgs("/w", "/s", "/p", "/r", "/a", "127.0.0.1:18080")
	n := len(with)
	if with[n-2] != "-net-allow" || with[n-1] != "127.0.0.1:18080" {
		t.Fatalf("expected trailing -net-allow, got %v", with)
	}
	for _, a := range mcpWorkerArgs("/w", "/s", "/p", "/r", "/a", "") {
		if a == "-net-allow" {
			t.Fatal("-net-allow must be absent when flag is empty")
		}
	}
}

// 보고서 029 P-2: MCP 로거 레벨은 전역 로거(-verbose)를 따른다.
func TestMCPRunner_LogLevelFollowsGlobalLogger(t *testing.T) {
	// id 없는 notification 프레임은 서버가 Debug 로그만 남기고 무시한다.
	const frame = `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	const debugMsg = "ignoring notification frame without id"

	tests := []struct {
		name      string
		level     slog.Level
		wantDebug bool
	}{
		{"전역 Debug면 MCP Debug 로그 출력", slog.LevelDebug, true},
		{"전역 Info면 MCP Debug 로그 미출력", slog.LevelInfo, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := slog.Default()
			t.Cleanup(func() { slog.SetDefault(prev) })
			slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: tc.level})))

			errOut := &bytes.Buffer{}
			runner := NewMCPRunner(strings.NewReader(frame), &bytes.Buffer{}, errOut, "", "", "", "", "", &dummyMCPExecutor{})
			if code := runner.Run(context.Background(), []string{"serve"}); code != domain.ExitSuccess {
				t.Fatalf("expected ExitSuccess, got %v (stderr: %s)", code, errOut.String())
			}
			if got := strings.Contains(errOut.String(), debugMsg); got != tc.wantDebug {
				t.Errorf("debug log present=%v, want %v (stderr: %q)", got, tc.wantDebug, errOut.String())
			}
		})
	}
}
