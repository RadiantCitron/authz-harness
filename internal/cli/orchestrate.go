package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/domain"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// OrchestrateRunner 는 오케스트레이터 서브프로세스 생성 및 제어를 담당하는 CLI 러너다.
type OrchestrateRunner struct {
	stdout       io.Writer
	stderr       io.Writer
	workspaceDir string
	statePath    string
	pubJWKSPath  string
	replayPath   string
	auditPath    string
	workerBin    string // 테스트 시 모의/커스텀 바이너리 주입 지원 (기본: os.Executable())
}

// NewOrchestrateRunner 는 OrchestrateRunner 인스턴스를 생성한다.
func NewOrchestrateRunner(
	stdout, stderr io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
) (*OrchestrateRunner, error) {
	return &OrchestrateRunner{
		stdout:       stdout,
		stderr:       stderr,
		workspaceDir: workspaceDir,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
		auditPath:    auditPath,
	}, nil
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
		tokenFlag        string
		actionFlag       string
		fileFlag         string
		dataFlag         string
		timeoutFlag      time.Duration
		injectRevokeFlag bool
		traceIDFlag      string
		workspaceFlag    string
		stateFlag        string
		pubJWKSFlag      string
		replayFlag       string
		auditFlag        string
	)

	fs.StringVar(&tokenFlag, "token", "", "서브에이전트에 주입할 축소 위임 Access Token (필수)")
	fs.StringVar(&actionFlag, "action", "file:read", "수행할 작업 (file:read / file:write / read / write)")
	fs.StringVar(&fileFlag, "file", "", "작업 대상 파일 상대 경로 (필수)")
	fs.StringVar(&dataFlag, "data", "", "쓰기 작업 시 기록할 내용")
	fs.DurationVar(&timeoutFlag, "timeout", 10*time.Second, "자식 프로세스 실행 타임아웃")
	fs.BoolVar(&injectRevokeFlag, "inject-revoke-before-io", false, "Gate 1 통과 후 I/O 직전 Grant Revoke 결함 주입 스위치")
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

	cleanAction := strings.ToLower(strings.TrimSpace(actionFlag))
	if cleanAction == "read" {
		cleanAction = "file:read"
	} else if cleanAction == "write" {
		cleanAction = "file:write"
	}

	if cleanAction != "file:read" && cleanAction != "file:write" {
		fmt.Fprintf(r.stderr, "Error: invalid -action: %s (must be read or write)\n", actionFlag)
		return domain.ExitBadInput
	}

	traceID := strings.TrimSpace(traceIDFlag)
	if traceID == "" {
		traceID = fmt.Sprintf("orch-%d", time.Now().UnixNano())
	}

	// 1. 감사 로그 기록기 초기화
	stack, err := app.BuildStack(app.AppConfig{AuditPath: auditFlag, VerifyOnly: true})
	if err != nil {
		fmt.Fprintf(r.stderr, "Error: failed to init audit writer: %v\n", err)
		return domain.ExitInternalError
	}
	defer stack.Close()
	auditWriter := stack.AuditWriter

	// 2. 바이너리 결정
	binPath := r.workerBin
	if binPath == "" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(r.stderr, "Error: failed to get executable path: %v\n", err)
			return domain.ExitInternalError
		}
		binPath = exe
	}

	// 상대 경로 파일인 경우 절대 경로로 정규화 (하위 프로세스 환경 차이 방지)
	absStateFlag, _ := filepath.Abs(stateFlag)
	absPubJWKSFlag, _ := filepath.Abs(pubJWKSFlag)
	absReplayFlag, _ := filepath.Abs(replayFlag)
	absAuditFlag, _ := filepath.Abs(auditFlag)
	absWorkspaceFlag, _ := filepath.Abs(workspaceFlag)

	// 3. Spawner 구성
	childArgs := []string{
		"subagent", "worker",
		"-workspace", absWorkspaceFlag,
		"-state-file", absStateFlag,
		"-pub-jwks-file", absPubJWKSFlag,
		"-replay-file", absReplayFlag,
		"-audit-file", absAuditFlag,
	}

	spawner, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath: binPath,
		Args:       childArgs,
		Limits:     orchestrator.Limits{Timeout: timeoutFlag},
		Audit:      auditWriter,
	})
	if err != nil {
		fmt.Fprintf(r.stderr, "Error: failed to init spawner: %v\n", err)
		return domain.ExitInternalError
	}

	// 4. 자식 워커 요청 프레임 구성
	subReq := subagent.SubagentRequest{
		Version:              "1.0",
		TraceID:              traceID,
		Token:                tokenFlag,
		Action:               cleanAction,
		FilePath:             fileFlag,
		Data:                 dataFlag,
		InjectRevokeBeforeIO: injectRevokeFlag,
	}

	// 5. 프로세스 스폰 및 종료 코드 수거
	result, err := spawner.Spawn(ctx, subReq)
	if err != nil {
		fmt.Fprintf(r.stderr, "Error: failed to spawn worker: %v\n", err)
		return domain.ExitInternalError
	}

	// 6. 결과 출력
	fmt.Fprintf(r.stdout, "=== Orchestrate Spawn Execution ===\n")
	fmt.Fprintf(r.stdout, "Trace ID: %s\n", result.TraceID)
	fmt.Fprintf(r.stdout, "Child Exit Code: %d\n", result.ExitCode)
	fmt.Fprintf(r.stdout, "Termination: %s\n", result.Termination)
	if result.Reason != "" {
		fmt.Fprintf(r.stdout, "Reason: %s\n", result.Reason)
	}
	fmt.Fprintf(r.stdout, "Duration: %v\n", result.Duration)

	if result.Response != nil {
		if result.Response.Reason != "" && result.Reason == "" {
			fmt.Fprintf(r.stdout, "Reason: %s\n", result.Response.Reason)
		}
		if result.Response.Output != "" {
			fmt.Fprintf(r.stdout, "Output:\n%s\n", result.Response.Output)
		}
		if result.Response.BytesRead > 0 {
			fmt.Fprintf(r.stdout, "Bytes Read: %d\n", result.Response.BytesRead)
		}
		if result.Response.BytesWritten > 0 {
			fmt.Fprintf(r.stdout, "Bytes Written: %d\n", result.Response.BytesWritten)
		}
		if result.Response.Error != "" {
			fmt.Fprintf(r.stderr, "Child Error: %s\n", result.Response.Error)
		}
	} else if result.StderrRaw != "" {
		fmt.Fprintf(r.stderr, "Child Stderr:\n%s\n", result.StderrRaw)
	}

	return domain.ExitCode(result.ExitCode)
}
