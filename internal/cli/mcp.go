package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/domain"
	"authz-harness/internal/mcp"
	"authz-harness/internal/observe/slogadapter"
	"authz-harness/internal/orchestrator"
)

// MCPRunner 는 `mcp` 서브커맨드를 주관하는 CLI 러너다.
type MCPRunner struct {
	in           io.Reader
	out          io.Writer
	errOut       io.Writer
	workspaceDir string
	statePath    string
	pubJWKSPath  string
	replayPath   string
	auditPath    string
	executor     mcp.Executor // 테스트 주입 지원 (nil일 경우 플래그 기반 SubprocessExecutor 생성)
	workerBin    string       // 테스트 지원 커스텀 바이너리 경로
}

// NewMCPRunner 는 MCPRunner 인스턴스를 생성한다.
func NewMCPRunner(
	in io.Reader, out, errOut io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
	executor mcp.Executor,
) *MCPRunner {
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
		in:           in,
		out:          out,
		errOut:       errOut,
		workspaceDir: workspaceDir,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
		auditPath:    auditPath,
		executor:     executor,
	}
}

// SetWorkerBinaryPath 는 자식 프로세스로 실행할 바이너리 경로를 재정의한다 (테스트 지원).
func (r *MCPRunner) SetWorkerBinaryPath(binPath string) {
	r.workerBin = binPath
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

	var (
		workspaceFlag string
		stateFlag     string
		pubJWKSFlag   string
		replayFlag    string
		auditFlag     string
		timeoutFlag   time.Duration
		netAllowFlag  string
	)

	fs.StringVar(&workspaceFlag, "workspace", r.workspaceDir, "격리된 Workspace 디렉터리 경로")
	fs.StringVar(&stateFlag, "state-file", r.statePath, "Zone B 상태 파일 경로")
	fs.StringVar(&pubJWKSFlag, "pub-jwks-file", r.pubJWKSPath, "Zone B 공개 검증 키(JWKS) 경로")
	fs.StringVar(&replayFlag, "replay-file", r.replayPath, "Zone B Replay 방지 원장 경로")
	fs.StringVar(&auditFlag, "audit-file", r.auditPath, "감사 로그 저장 파일 경로")
	fs.DurationVar(&timeoutFlag, "timeout", 10*time.Second, "자식 프로세스 실행 타임아웃")

	fs.StringVar(&netAllowFlag, "net-allow", "", "워커에 그대로 넘길 net:fetch 허용 host:port 목록 (쉼표 구분)")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	// 전역 로거(main 의 -verbose)가 Debug 를 허용하면 MCP 로거도 Debug 로 맞춘다.
	logLevel := slog.LevelInfo
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(r.errOut, &slog.HandlerOptions{Level: logLevel, ReplaceAttr: slogadapter.RedactReplaceAttr}))

	executor := r.executor
	if executor == nil {
		// 1. 감사 로그 기록기 초기화
		stack, err := app.BuildStack(app.AppConfig{AuditPath: auditFlag, VerifyOnly: true})
		if err != nil {
			fmt.Fprintf(r.errOut, "Error: failed to init audit writer: %v\n", err)
			return domain.ExitInternalError
		}
		defer stack.Close()
		auditWriter := stack.AuditWriter

		// 2. 바이너리 결정
		binPath := r.workerBin
		if binPath == "" {
			exe, err := os.Executable()
			if err != nil {
				fmt.Fprintf(r.errOut, "Error: failed to get executable path: %v\n", err)
				return domain.ExitInternalError
			}
			binPath = exe
		}

		absStateFlag, _ := filepath.Abs(stateFlag)
		absPubJWKSFlag, _ := filepath.Abs(pubJWKSFlag)
		absReplayFlag, _ := filepath.Abs(replayFlag)
		absAuditFlag, _ := filepath.Abs(auditFlag)
		absWorkspaceFlag, _ := filepath.Abs(workspaceFlag)

		childArgs := mcpWorkerArgs(absWorkspaceFlag, absStateFlag, absPubJWKSFlag, absReplayFlag, absAuditFlag, netAllowFlag, logLevel == slog.LevelDebug)

		spawner, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
			BinaryPath: binPath,
			Args:       childArgs,
			Limits:     orchestrator.Limits{Timeout: timeoutFlag},
			Audit:      auditWriter,
		})
		if err != nil {
			fmt.Fprintf(r.errOut, "Error: failed to create spawner: %v\n", err)
			return domain.ExitInternalError
		}

		executor = mcp.NewSubprocessExecutor(spawner)
	}

	server := mcp.NewServer(r.in, r.out, r.errOut, executor, logger)

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

// mcpWorkerArgs 는 MCP 어댑터가 스폰하는 subagent worker 의 인자를 조립한다. -net-allow 는 값이 있을 때만, -verbose 는 verbose 일 때만 넘긴다.
func mcpWorkerArgs(workspace, stateFile, pubJWKS, replay, auditFile, netAllow string, verbose bool) []string {
	args := []string{
		"subagent", "worker",
		"-workspace", workspace,
		"-state-file", stateFile,
		"-pub-jwks-file", pubJWKS,
		"-replay-file", replay,
		"-audit-file", auditFile,
	}
	if strings.TrimSpace(netAllow) != "" {
		args = append(args, "-net-allow", netAllow)
	}
	if verbose {
		args = append(args, "-verbose")
	}
	return args
}
