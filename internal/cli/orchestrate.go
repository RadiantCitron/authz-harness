// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(orchestrate.go)은 부모 오케스트레이터로서 자식 서브에이전트 프로세스를 생성·통제하는 `orchestrate` 서브커맨드 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. 축소 위임 기반 서브프로세스 스폰 (Downscoped Subprocess Spawning):
//    - spawn: 부모가 발급받거나 축소 위임(Downscoped)한 토큰(-token)을 자식 프로세스에 주입하여 실행.
//    - buildWorkerSpawner 를 통해 자식이 실행될 바이너리, 절대 경로 정규화, 타임아웃, 프로세스 그룹 제한을 일원화 설정.
// 2. 프로세스 격리 및 자원 한계 (Process Confinement & Limits):
//    - 자식 프로세스는 독립된 프로세스 그룹(Process Group)으로 기동되며 타임아웃 초과 시 자식 트리를 강제 회수한다.
// 3. Zero Leakage 및 원시 토큰 마스킹 (Redact Raw Tokens):
//    - renderSpawnResult: 자식 프로세스가 출력한 stderr 나 에러 메시지에 Bearer 토큰이 노출되지 않도록
//      domain.RedactRawTokens 로 마스킹 처리한 후 콘솔에 출력한다.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// OrchestrateRunner 는 오케스트레이터 서브프로세스 생성 및 제어를 담당하는 CLI 러너다.
// 자식 워커에게 안전하게 인자를 전달하고 실행 결과를 수거하여 출력한다.
type OrchestrateRunner struct {
	stdout       io.Writer // 표준 출력 스트림
	stderr       io.Writer // 표준 에러 스트림
	workspaceDir string    // 워크스페이스 디렉터리 경로
	statePath    string    // Zone B 상태 파일 경로
	pubJWKSPath  string    // Zone B 공개 키(JWKS) 경로
	replayPath   string    // Replay 방지 원장 경로
	auditPath    string    // 감사 로그 파일 경로
	workerBin    string    // 테스트 시 모의/커스텀 바이너리 주입 지원 (기본: os.Executable())
}

// NewOrchestrateRunner 는 OrchestrateRunner 인스턴스를 생성한다.
func NewOrchestrateRunner(
	stdout, stderr io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
) *OrchestrateRunner {
	return &OrchestrateRunner{
		stdout:       stdout,
		stderr:       stderr,
		workspaceDir: workspaceDir,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
		auditPath:    auditPath,
	}
}

// SetWorkerBinaryPath 는 자식 프로세스로 실행할 바이너리 경로를 재정의한다 (테스트 지원).
func (r *OrchestrateRunner) SetWorkerBinaryPath(binPath string) {
	r.workerBin = binPath
}

// Run 은 orchestrate 서브커맨드 인자를 파싱하고 실행한다.
// 문법: authz-harness orchestrate spawn [flags]
func (r *OrchestrateRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		fmt.Fprintln(r.stderr, "Error: orchestrate subcommand required (e.g. 'spawn')")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	if subcmd != "spawn" {
		fmt.Fprintf(r.stderr, "Error: unknown orchestrate subcommand: %s\n", subcmd)
		return domain.ExitBadInput
	}

	fs := flag.NewFlagSet("orchestrate spawn", flag.ContinueOnError)
	fs.SetOutput(r.stderr)

	var (
		tokenFlag     string
		actionFlag    string
		fileFlag      string
		dataFlag      string
		timeoutFlag   time.Duration
		traceIDFlag   string
		workspaceFlag string
		stateFlag     string
		pubJWKSFlag   string
		replayFlag    string
		auditFlag     string
	)

	fs.StringVar(&tokenFlag, "token", "", "서브에이전트에 주입할 축소 위임 Access Token (필수)")
	fs.StringVar(&actionFlag, "action", "file:read", "수행할 작업 (file:read / file:write / net:fetch / exec:run / read / write)")
	fs.StringVar(&fileFlag, "file", "", "작업 대상 파일 상대 경로 (필수)")
	fs.StringVar(&dataFlag, "data", "", "쓰기 작업 시 기록할 내용")
	fs.DurationVar(&timeoutFlag, "timeout", 10*time.Second, "자식 프로세스 실행 타임아웃")
	fs.StringVar(&traceIDFlag, "trace-id", "", "분산 추적 식별자 (미지정 시 자동 생성)")

	fs.StringVar(&workspaceFlag, "workspace", r.workspaceDir, "격리된 Workspace 디렉터리 경로")
	fs.StringVar(&stateFlag, "state-file", r.statePath, "Zone B 상태 파일 경로")
	fs.StringVar(&pubJWKSFlag, "pub-jwks-file", r.pubJWKSPath, "Zone B 공개 검증 키(JWKS) 경로")
	fs.StringVar(&replayFlag, "replay-file", r.replayPath, "Zone B Replay 방지 원장 경로")
	fs.StringVar(&auditFlag, "audit-file", r.auditPath, "감사 로그 저장 파일 경로")

	if err := fs.Parse(args[1:]); err != nil {
		return domain.ExitBadInput
	}

	// 필수 인자 검증
	if strings.TrimSpace(tokenFlag) == "" {
		fmt.Fprintln(r.stderr, "Error: -token is required")
		return domain.ExitBadInput
	}
	if strings.TrimSpace(fileFlag) == "" {
		fmt.Fprintln(r.stderr, "Error: -file is required")
		return domain.ExitBadInput
	}

	parsedAction, err := domain.ParseAction(actionFlag)
	if err != nil {
		fmt.Fprintf(r.stderr, "Error: invalid -action: %v\n", err)
		return domain.ExitBadInput
	}
	cleanAction := string(parsedAction)

	traceID := strings.TrimSpace(traceIDFlag)
	if traceID == "" {
		traceID = fmt.Sprintf("orch-%d", time.Now().UnixNano())
	}

	// 1. Spawner 구성 (감사 로그 스택, 바이너리, 절대경로 정규화 포함)
	spawner, stack, err := buildWorkerSpawner(workerSpawnerConfig{
		WorkerBin:     r.workerBin,
		AuditPath:     auditFlag,
		WorkspacePath: workspaceFlag,
		StatePath:     stateFlag,
		PubJWKSPath:   pubJWKSFlag,
		ReplayPath:    replayFlag,
		Timeout:       timeoutFlag,
	}, r.stderr)
	if err != nil {
		return domain.ExitInternalError
	}
	defer stack.Close()

	// 2. 자식 워커 요청 프레임 구성
	subReq := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  traceID,
		Token:    tokenFlag,
		Action:   cleanAction,
		FilePath: fileFlag,
		Data:     dataFlag,
	}

	// 3. 프로세스 스폰 및 종료 코드 수거
	result, err := spawner.Spawn(ctx, subReq)
	if err != nil {
		fmt.Fprintf(r.stderr, "Error: failed to spawn worker: %v\n", err)
		return domain.ExitInternalError
	}

	// 4. 결과 출력
	return renderSpawnResult(r.stdout, r.stderr, result)
}

// renderSpawnResult 는 자식 실행 결과를 출력하고 자식 종료 코드를 반환한다.
// 자식이 낸 stderr·오류 문자열은 원시 토큰이 섞여 있을 수 있어 stderr 로 내보내기 전에 마스킹한다.
func renderSpawnResult(stdout, stderr io.Writer, result *orchestrator.SpawnResult) domain.ExitCode {
	fmt.Fprintf(stdout, "=== Orchestrate Spawn Execution ===\n")
	fmt.Fprintf(stdout, "Trace ID: %s\n", result.TraceID)
	fmt.Fprintf(stdout, "Child Exit Code: %d\n", result.ExitCode)
	fmt.Fprintf(stdout, "Termination: %s\n", result.Termination)
	if result.Reason != "" {
		fmt.Fprintf(stdout, "Reason: %s\n", result.Reason)
	}
	fmt.Fprintf(stdout, "Duration: %v\n", result.Duration)

	if result.Response != nil {
		if result.Response.Reason != "" && result.Reason == "" {
			fmt.Fprintf(stdout, "Reason: %s\n", result.Response.Reason)
		}
		if result.Response.Output != "" {
			fmt.Fprintf(stdout, "Output:\n%s\n", result.Response.Output)
		}
		if result.Response.BytesRead > 0 {
			fmt.Fprintf(stdout, "Bytes Read: %d\n", result.Response.BytesRead)
		}
		if result.Response.BytesWritten > 0 {
			fmt.Fprintf(stdout, "Bytes Written: %d\n", result.Response.BytesWritten)
		}
		if result.Response.Error != "" {
			fmt.Fprintf(stderr, "Child Error: %s\n", domain.RedactRawTokens(result.Response.Error))
		}
	} else if result.StderrRaw != "" {
		fmt.Fprintf(stderr, "Child Stderr:\n%s\n", domain.RedactRawTokens(result.StderrRaw))
	}

	return domain.ExitCode(result.ExitCode)
}
