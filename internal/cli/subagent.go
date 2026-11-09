// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(subagent.go)은 격리된 자식 서브에이전트 워커 프로세스의 진입점인 `subagent worker` 서브커맨드 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. OS 프로세스 격리 및 Zone B 한정 (Process Confinement & Zone B Boundary):
//    - 서브에이전트는 부모 프로세스로부터 포크/스폰되어 독립된 프로세스로 실행된다.
//    - app.BuildStack 호출 시 VerifyOnly: true 모드를 사용하여 Zone A 비공개키에 일체 접근하지 않으며,
//      Zone B의 공개 검증 키(JWKS), 상태 파일, Replay 원장만을 바탕으로 인가를 집행한다.
// 2. 단방향 JSON IPC 스트리밍 (Stream-based Subagent Worker):
//    - stdin 을 통해 단일 요청 JSON 프레임(SubagentRequest)을 수신하고,
//      PEP 게이트웨이 파이프라인을 거쳐 도구를 실행한 뒤 stdout 으로 JSON 응답(SubagentResponse)을 반환한다.
// 3. 네트워크 및 관측 격리 (NetGuard & Local Observation):
//    - -net-allow 플래그로 지정된 호스트:포트 목록만 netguard.NewGuard 로 필터링하여 SSRF 공격을 차단한다.
//    - -verbose 플래그 지정 시 전역 slog 를 오염시키지 않고 해당 워커 전용 slogadapter(Debug 레벨, 토큰 마스킹 적용)를 주입한다.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"authz-harness/internal/app"
	"authz-harness/internal/domain"
	"authz-harness/internal/netguard"
	"authz-harness/internal/observe"
	"authz-harness/internal/observe/slogadapter"
	"authz-harness/internal/subagent"
)

// SubagentRunner 는 자식 서브에이전트 프로세스 진입점을 담당하는 CLI 러너다.
// stdin 스트림으로부터 JSON 명령을 읽고 PEP 게이트웨이를 통해 실행 후 stdout 에 결과를 쓴다.
type SubagentRunner struct {
	stdout       io.Writer // 표준 출력 스트림 (JSON 응답 반환)
	stderr       io.Writer // 표준 에러 스트림 (디버그/에러 로그)
	stdin        io.Reader // 표준 입력 스트림 (JSON 요청 수신, 테스트 주입 가능)
	workspaceDir string    // 워커 전용 격리 워크스페이스
	statePath    string    // Zone B 상태 파일 경로
	pubJWKSPath  string    // Zone B 공개 키(JWKS) 경로
	replayPath   string    // Replay 방지 원장 경로
	auditPath    string    // 감사 로그 파일 경로
}

// NewSubagentRunner 는 자식 서브에이전트 실행을 위한 SubagentRunner 인스턴스를 생성한다.
func NewSubagentRunner(
	stdout, stderr io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
) *SubagentRunner {
	return &SubagentRunner{
		stdout:       stdout,
		stderr:       stderr,
		stdin:        os.Stdin,
		workspaceDir: workspaceDir,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
		auditPath:    auditPath,
	}
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
		verboseFlag   bool
	)

	fs.StringVar(&workspaceFlag, "workspace", r.workspaceDir, "격리된 Workspace 디렉터리 경로")
	fs.StringVar(&stateFlag, "state-file", r.statePath, "Zone B 상태 파일 경로")
	fs.StringVar(&pubJWKSFlag, "pub-jwks-file", r.pubJWKSPath, "Zone B 공개 검증 키(JWKS) 경로")
	fs.StringVar(&replayFlag, "replay-file", r.replayPath, "Zone B Replay 방지 원장 경로")
	fs.StringVar(&auditFlag, "audit-file", r.auditPath, "감사 로그 저장 파일 경로")

	fs.StringVar(&netAllowFlag, "net-allow", "", "net:fetch 허용 host:port 목록 (쉼표 구분, 예: 127.0.0.1:18080). 비면 전부 거부")

	fs.BoolVar(&verboseFlag, "verbose", false, "PEP 관측 Debug 로그를 stderr 로 출력")

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

	// -verbose: 전역 로거는 건드리지 않고 이 worker 의 PEP 관측자만 Debug 로 주입한다.
	var obs observe.Observer
	if verboseFlag {
		obs = slogadapter.New(slog.New(slog.NewTextHandler(r.stderr, &slog.HandlerOptions{
			Level:       slog.LevelDebug,
			ReplaceAttr: slogadapter.RedactReplaceAttr,
		})))
	}

	// 1. 단일 합성 루트(AppStack)를 통한 검증 전용 컴포넌트 조립
	stack, err := app.BuildStack(app.AppConfig{
		WorkspaceDir: workspaceFlag,
		StatePath:    stateFlag,
		PubJWKSPath:  pubJWKSFlag,
		ReplayPath:   replayFlag,
		AuditPath:    auditFlag,
		NetAllowList: netAllow,
		Observer:     obs,
		VerifyOnly:   true, // 자식 서브에이전트는 Zone A(개인키) 미접근 원칙 준수
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
