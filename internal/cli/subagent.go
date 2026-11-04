package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"authz-harness/internal/app"
	"authz-harness/internal/domain"
	"authz-harness/internal/netguard"
	"authz-harness/internal/subagent"
)

// SubagentRunner 는 자식 서브에이전트 프로세스 진입점을 담당하는 CLI 러너다.
type SubagentRunner struct {
	stdout       io.Writer
	stderr       io.Writer
	stdin        io.Reader
	workspaceDir string
	statePath    string
	pubJWKSPath  string
	replayPath   string
	auditPath    string
}

// NewSubagentRunner 는 자식 서브에이전트 실행을 위한 SubagentRunner 인스턴스를 생성한다.
func NewSubagentRunner(
	stdout, stderr io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
) (*SubagentRunner, error) {
	return &SubagentRunner{
		stdout:       stdout,
		stderr:       stderr,
		stdin:        os.Stdin,
		workspaceDir: workspaceDir,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
		auditPath:    auditPath,
	}, nil
}

// SetStdin 은 테스트 시 stdin 스트림을 재정의할 수 있도록 지원한다.
func (r *SubagentRunner) SetStdin(in io.Reader) {
	r.stdin = in
}

// Run 은 subagent 서브커맨드 인자를 파싱하고 작업을 실행한다.
// 문법: authz-harness subagent worker [flags]
func (r *SubagentRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		fmt.Fprintln(r.stderr, "Error: subagent subcommand required (e.g. 'worker')")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	if subcmd != "worker" {
		fmt.Fprintf(r.stderr, "Error: unknown subagent subcommand: %s\n", subcmd)
		return domain.ExitBadInput
	}

	fs := flag.NewFlagSet("subagent worker", flag.ContinueOnError)
	fs.SetOutput(r.stderr)

	var (
		workspaceFlag string
		stateFlag     string
		pubJWKSFlag   string
		replayFlag    string
		auditFlag     string
		netAllowFlag  string
	)

	fs.StringVar(&workspaceFlag, "workspace", r.workspaceDir, "격리된 Workspace 디렉터리 경로")
	fs.StringVar(&stateFlag, "state-file", r.statePath, "Zone B 상태 파일 경로")
	fs.StringVar(&pubJWKSFlag, "pub-jwks-file", r.pubJWKSPath, "Zone B 공개 검증 키(JWKS) 경로")
	fs.StringVar(&replayFlag, "replay-file", r.replayPath, "Zone B Replay 방지 원장 경로")
	fs.StringVar(&auditFlag, "audit-file", r.auditPath, "감사 로그 저장 파일 경로")

	fs.StringVar(&netAllowFlag, "net-allow", "", "net:fetch 허용 host:port 목록 (쉼표 구분, 예: 127.0.0.1:18080). 비면 전부 거부")

	if err := fs.Parse(args[1:]); err != nil {
		return domain.ExitBadInput
	}

	var netAllow []string
	if strings.TrimSpace(netAllowFlag) != "" {
		for _, e := range strings.Split(netAllowFlag, ",") {
			netAllow = append(netAllow, strings.TrimSpace(e))
		}
		if _, err := netguard.NewGuard(netAllow, 0, 0); err != nil {
			fmt.Fprintf(r.stderr, "Error: invalid -net-allow: %v\n", err)
			return domain.ExitBadInput
		}
	}

	// 1. 단일 합성 루트(AppStack)를 통한 검증 전용 컴포넌트 조립
	stack, err := app.BuildStack(app.AppConfig{
		WorkspaceDir:             workspaceFlag,
		StatePath:                stateFlag,
		PubJWKSPath:              pubJWKSFlag,
		ReplayPath:               replayFlag,
		AuditPath:                auditFlag,
		NetAllowList:             netAllow,
		EnableRevokeBeforeIOHook: true, // 결함 주입: req.InjectRevokeBeforeIO 시 I/O 직전 모든 Grant 회수
		VerifyOnly:               true, // 자식 서브에이전트는 Zone A(개인키) 미접근 원칙 준수
	})
	if err != nil {
		fmt.Fprintf(r.stderr, "Error: failed to build subagent stack: %v\n", err)
		return domain.ExitInternalError
	}
	defer stack.Close()

	worker, err := subagent.NewWorker(stack.PEP)
	if err != nil {
		fmt.Fprintf(r.stderr, "Error: failed to init subagent worker: %v\n", err)
		return domain.ExitInternalError
	}

	// 2. stdin 스트림에서 JSON 프레임 읽어 실행 및 stdout 출력
	stdinReader := r.stdin
	if stdinReader == nil {
		stdinReader = os.Stdin
	}

	exitCode := worker.ExecuteStream(ctx, stdinReader, r.stdout)
	return domain.ExitCode(exitCode)
}
