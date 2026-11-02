package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"authz-harness/internal/domain"
	"authz-harness/internal/mcp"
)

// MCPRunner 는 `mcp` 서브커맨드를 주관하는 CLI 러너다.
type MCPRunner struct {
	in       io.Reader
	out      io.Writer
	errOut   io.Writer
	executor mcp.Executor
}

// NewMCPRunner 는 MCPRunner 인스턴스를 생성한다.
func NewMCPRunner(in io.Reader, out, errOut io.Writer, executor mcp.Executor) *MCPRunner {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	return &MCPRunner{
		in:       in,
		out:      out,
		errOut:   errOut,
		executor: executor,
	}
}

// Run 은 mcp 하위 명령어를 파싱하고 실행한다.
func (r *MCPRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		r.printUsage()
		return domain.ExitBadInput
	}

	subcmd := args[0]
	switch subcmd {
	case "serve":
		return r.runServe(ctx, args[1:])
	default:
		fmt.Fprintf(r.errOut, "Error: unknown mcp command '%s'\n", subcmd)
		r.printUsage()
		return domain.ExitBadInput
	}
}

func (r *MCPRunner) runServe(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	logger := slog.New(slog.NewTextHandler(r.errOut, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server := mcp.NewServer(r.in, r.out, r.errOut, r.executor, logger)

	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(r.errOut, "Error: mcp server encountered error: %v\n", err)
		return domain.ExitInternalError
	}

	return domain.ExitSuccess
}

func (r *MCPRunner) printUsage() {
	fmt.Fprintln(r.errOut, "Usage: authz-harness mcp <command> [options]")
	fmt.Fprintln(r.errOut, "Commands:")
	fmt.Fprintln(r.errOut, "  serve    stdio 기반 MCP JSON-RPC 2.0 어댑터 서버 시작")
}
