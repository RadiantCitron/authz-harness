// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(mcp.go)은 LLM 에이전트 환경(Claude Desktop 등)과 표준 프로토콜로 연동되는 Model Context Protocol (MCP) stdio 서버 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. JSON-RPC 2.0 stdio 어댑터 (Model Context Protocol Gateway):
//    - serve: 표준 입출력(stdio)을 통해 들어오는 MCP 도구 호출(CallTool, ListTools)을 처리.
//    - LLM 클라이언트가 하네스의 보안 도구(file_read, file_write 등)를 호출할 때 축소 위임 토큰을 요구하고 인가를 집행.
// 2. 격리된 서브프로세스 실행 (Subprocess Executor):
//    - mcp.Executor 인터페이스를 통해 도구 실행 요청을 격리된 워커 서브프로세스(SubprocessSpawner)로 전달.
//    - 메인 MCP 서버 프로세스는 관리/중계 역할만 수행하며, 실제 도구 I/O는 격리된 워커 프로세스에서 수행된다.
// 3. 토큰 마스킹 및 관측성 (Redacted Observability):
//    - -verbose 플래그와 연동되어 slogadapter.RedactReplaceAttr 로 원시 토큰 유출을 원천 차단하면서
//      stderr 로 운영 디버깅 로그를 출력한다.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/mcp"
	"authz-harness/internal/observe/slogadapter"
)

// MCPRunner 는 `mcp` 서브커맨드(serve)를 주관하는 CLI 러너다.
// stdio 기반 MCP 서버를 기동하고 SubprocessExecutor 를 통해 격리 실행을 조율한다.
type MCPRunner struct {
	in           io.Reader    // 표준 입력 스트림 (MCP JSON-RPC 수신)
	out          io.Writer    // 표준 출력 스트림 (MCP JSON-RPC 응답)
	errOut       io.Writer    // 표준 에러 스트림 (운영 로그 및 에러 메시지)
	workspaceDir string       // 워커 전용 워크스페이스 디렉터리 경로
	statePath    string       // Zone B 상태 파일 경로
	pubJWKSPath  string       // Zone B 공개 키(JWKS) 경로
	replayPath   string       // Replay 방지 원장 경로
	auditPath    string       // 감사 로그 파일 경로
	executor     mcp.Executor // 테스트 주입 지원 (nil일 경우 플래그 기반 SubprocessExecutor 생성)
	workerBin    string       // 테스트 지원 커스텀 바이너리 경로
	privKeyPath  string       // Zone A 개인키 경로 (-confine 의 보호 루트 계산용. 워커에는 넘기지 않음)
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

// SetPrivKeyPath 는 -confine 의 보호 루트 계산에 쓸 Zone A 개인키 경로를 지정한다.
func (r *MCPRunner) SetPrivKeyPath(path string) {
	r.privKeyPath = path
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

// runServe 는 stdio JSON-RPC 2.0 기반 MCP 서버를 시작한다.
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
		confineFlag   bool
	)

	fs.StringVar(&workspaceFlag, "workspace", r.workspaceDir, "격리된 Workspace 디렉터리 경로")
	fs.StringVar(&stateFlag, "state-file", r.statePath, "Zone B 상태 파일 경로")
	fs.StringVar(&pubJWKSFlag, "pub-jwks-file", r.pubJWKSPath, "Zone B 공개 검증 키(JWKS) 경로")
	fs.StringVar(&replayFlag, "replay-file", r.replayPath, "Zone B Replay 방지 원장 경로")
	fs.StringVar(&auditFlag, "audit-file", r.auditPath, "감사 로그 저장 파일 경로")
	fs.DurationVar(&timeoutFlag, "timeout", 10*time.Second, "자식 프로세스 실행 타임아웃")

	fs.StringVar(&netAllowFlag, "net-allow", "", "워커에 그대로 넘길 net:fetch 허용 host:port 목록 (쉼표 구분)")
	fs.BoolVar(&confineFlag, "confine", false, "워커를 OS 커널 격리(Seatbelt/Landlock) 아래에서 기동한다. 적용할 수 없으면 거부(16). 격리 중에는 -net-allow 의 포트만 연결을 허용한다")

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
		spawner, stack, err := buildWorkerSpawner(workerSpawnerConfig{
			WorkerBin:     r.workerBin,
			AuditPath:     auditFlag,
			WorkspacePath: workspaceFlag,
			StatePath:     stateFlag,
			PubJWKSPath:   pubJWKSFlag,
			ReplayPath:    replayFlag,
			NetAllow:      netAllowFlag,
			Verbose:       logLevel == slog.LevelDebug,
			Timeout:       timeoutFlag,
			Confine:       confineFlag,
			PrivKeyPath:   r.privKeyPath,
		}, r.errOut)
		if err != nil {
			return domain.ExitInternalError
		}
		defer stack.Close()

		executor = mcp.NewSubprocessExecutor(spawner, mcp.WithLogger(logger))
	}

	server := mcp.NewServer(r.in, r.out, r.errOut, executor, logger)

	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(r.errOut, "Error: mcp server encountered error: %v\n", err)
		return domain.ExitInternalError
	}

	return domain.ExitSuccess
}

// printUsage 는 mcp 서브커맨드의 사용법 가이드를 출력한다.
func (r *MCPRunner) printUsage() {
	fmt.Fprintln(r.errOut, "Usage: authz-harness mcp <command> [options]")
	fmt.Fprintln(r.errOut, "Commands:")
	fmt.Fprintln(r.errOut, "  serve    stdio 기반 MCP JSON-RPC 2.0 어댑터 서버 시작")
}
