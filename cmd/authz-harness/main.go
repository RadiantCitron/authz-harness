// Package main 은 authz-harness 의 최상위 CLI 진입점이다.
//
// [CLI 아키텍처 및 출력 삼분(Tri-Separation) 원칙]
// 1. 삼중 출력 분리:
//   - CLI 출력 (stdout): 하네스 러너 및 사용자를 위한 결과 출력 (Formatter).
//   - 운영 로그 (stderr): log/slog 기반의 디버깅 및 진단 로그 (ReplaceAttr 로 원시 토큰 자동 마스킹).
//   - 감사 증거 (audit.jsonl): audit.Writer 를 통한 불변의 보안 인가 판정 전용 해시 체인 이벤트.
//
// 2. 단일 책임 서브커맨드 라우팅:
//   - grant, approval, pdp, keys, token, pep, orchestrate, subagent, audit, run, mcp, confine-exec 등
//     개별 책임 단위의 서브커맨드 러너로 인자를 위임하고 표준 종료 코드를 반환한다.
//
// 3. 결정론적 종료 코드 (Fail-Closed Exit Codes):
//   - 0: 성공 (ExitSuccess)
//   - 10: 입력 인자 결함 (ExitBadInput)
//   - 11: 토큰 무효 (ExitInvalidToken)
//   - 12: 인가 거부 (ExitAuthzDenied)
//   - 13: 경계 탈출 (ExitBoundaryEscaped)
//   - 14: 도구 실행 실패 (ExitToolExecution)
//   - 15: 감사 실패 (ExitAuditFailure)
//   - 16: 내부 시스템 오류 (ExitInternalError)
//   - 18: 사람 승인 필요 (ExitApprovalRequired)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/cli"
	"authz-harness/internal/domain"
	"authz-harness/internal/observe/slogadapter"
)

// Version 은 하네스의 현재 시맨틱 버전 번호다.
const Version = "0.1.0"

func main() {
	var (
		showVersion  bool
		auditPath    string
		statePath    string
		privKeyPath  string
		pubJWKSPath  string
		replayPath   string
		workspaceDir string
		verbose      bool
	)

	flag.BoolVar(&showVersion, "version", false, "프로그램 버전 출력")
	flag.StringVar(&auditPath, "audit-file", "audit.jsonl", "감사 로그 저장 파일 경로")
	flag.StringVar(&statePath, "state-file", ".authz-state/public/grants_state.json", "Zone B 상태 파일 경로")
	flag.StringVar(&privKeyPath, "priv-key-file", ".authz-state/private/signing_keys.priv.json", "Zone A 비밀 서명 키 저장소 경로")
	flag.StringVar(&pubJWKSPath, "pub-jwks-file", ".authz-state/public/jwks.pub.json", "Zone B 공개 검증 키(JWKS) 경로")
	flag.StringVar(&replayPath, "replay-file", ".authz-state/public/replay_ledger.json", "Zone B Replay 방지 원장 경로")
	flag.StringVar(&workspaceDir, "workspace", "workspace", "격리된 Workspace 디렉터리 경로")
	flag.BoolVar(&verbose, "verbose", false, "운영 디버그 로그 활성화 (stderr)")
	flag.Parse()

	// 1. 운영 로그 (Ops Log) 초기화: stderr로 출력하여 CLI stdout 및 audit.jsonl과 분리 (Tri-Separation)
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel, ReplaceAttr: slogadapter.RedactReplaceAttr}))
	slog.SetDefault(logger)

	// 2. CLI 포매터 (인간 대상 표준 출력)
	formatter := cli.NewFormatter(os.Stdout)

	if showVersion {
		formatter.PrintBanner(Version)
		os.Exit(int(domain.ExitSuccess))
	}

	logger.Debug("authz-harness starting", "version", Version, "audit_file", auditPath, "state_file", statePath)

	// 서브커맨드 라우팅 확인
	args := flag.Args()
	if len(args) > 0 {
		subcmd := args[0]
		switch subcmd {
		case "grant":
			grantRunner, err := cli.NewGrantRunner(os.Stdout, os.Stderr, statePath, auditPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to initialize grant runner: %v\n", err)
				os.Exit(int(domain.ExitInternalError))
			}
			exitCode := grantRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "approval":
			approvalRunner, err := cli.NewApprovalRunner(os.Stdout, os.Stderr, statePath, auditPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to initialize approval runner: %v\n", err)
				os.Exit(int(domain.ExitInternalError))
			}
			exitCode := approvalRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "pdp":
			pdpRunner, err := cli.NewPDPRunner(os.Stdout, os.Stderr, statePath, auditPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to initialize pdp runner: %v\n", err)
				os.Exit(int(domain.ExitInternalError))
			}
			exitCode := pdpRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "keys":
			keysRunner, err := cli.NewKeysRunner(os.Stdout, os.Stderr, privKeyPath, pubJWKSPath, auditPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to initialize keys runner: %v\n", err)
				os.Exit(int(domain.ExitInternalError))
			}
			exitCode := keysRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "token":
			tokenRunner, err := cli.NewTokenRunner(os.Stdout, os.Stderr, statePath, privKeyPath, pubJWKSPath, replayPath, auditPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to initialize token runner: %v\n", err)
				os.Exit(int(domain.ExitInternalError))
			}
			exitCode := tokenRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "pep":
			pepRunner, err := cli.NewPEPRunner(os.Stdout, os.Stderr, workspaceDir, statePath, pubJWKSPath, replayPath, auditPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to initialize pep runner: %v\n", err)
				os.Exit(int(domain.ExitInternalError))
			}
			exitCode := pepRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "orchestrate":
			orchRunner := cli.NewOrchestrateRunner(os.Stdout, os.Stderr, workspaceDir, statePath, pubJWKSPath, replayPath, auditPath)
			exitCode := orchRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "subagent":
			subRunner := cli.NewSubagentRunner(os.Stdout, os.Stderr, workspaceDir, statePath, pubJWKSPath, replayPath, auditPath)
			exitCode := subRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "confine-exec": // 숨김 하위명령: 신뢰 런처 (사용법에 노출하지 않음)
			os.Exit(int(cli.RunConfineExec(args[1:], os.Stderr)))
		case "run":
			runRunner := cli.NewRunRunner(os.Stdout, os.Stderr, "")
			exitCode := runRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "audit":
			auditRunner := cli.NewAuditRunner(os.Stdout, os.Stderr, auditPath, privKeyPath, pubJWKSPath)
			exitCode := auditRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		case "mcp":
			mcpRunner := cli.NewMCPRunner(os.Stdin, os.Stdout, os.Stderr, workspaceDir, statePath, pubJWKSPath, replayPath, auditPath, nil)
			exitCode := mcpRunner.Run(context.Background(), args[1:])
			os.Exit(int(exitCode))
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", subcmd)
			os.Exit(int(domain.ExitBadInput))
		}
	}

	// 3. 서브커맨드 미지정 시 기본 시동 스모크 및 안내
	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize audit writer: %v\n", err)
		os.Exit(int(domain.ExitInternalError))
	}
	defer auditWriter.Close()

	initEvent := audit.Event{
		Timestamp: time.Now().UTC(),
		TraceID:   fmt.Sprintf("boot-%d", time.Now().UnixNano()),
		Step:      "harness.boot",
		Actor:     "harness-cli",
		Action:    "harness.started",
		Success:   true,
		Metadata: map[string]interface{}{
			"version": Version,
		},
	}
	if err := auditWriter.Log(initEvent); err != nil {
		logger.Error("failed to record startup audit event", "error", err)
		os.Exit(int(domain.ExitAuditFailure))
	}

	formatter.PrintBanner(Version)
	fmt.Println("CLI 및 감사/운영로그 3중 배선 골격이 정상 작동 중입니다.")
	fmt.Printf("감사 로그 저장 위치: %s\n", auditPath)
	fmt.Printf("상태 파일 저장 위치: %s\n", statePath)
}
