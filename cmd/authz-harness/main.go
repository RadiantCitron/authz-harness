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
)

const Version = "0.1.0"

func main() {
	var (
		showVersion bool
		auditPath   string
		statePath   string
		verbose     bool
	)

	flag.BoolVar(&showVersion, "version", false, "프로그램 버전 출력")
	flag.StringVar(&auditPath, "audit-file", "audit.jsonl", "감사 로그 저장 파일 경로")
	flag.StringVar(&statePath, "state-file", ".authz-state/public/grants_state.json", "Zone B 상태 파일 경로")
	flag.BoolVar(&verbose, "verbose", false, "운영 디버그 로그 활성화 (stderr)")
	flag.Parse()

	// 1. 운영 로그 (Ops Log) 초기화: stderr로 출력하여 CLI stdout 및 audit.jsonl과 분리 (Tri-Separation)
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
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
		case "pdp":
			pdpRunner, err := cli.NewPDPRunner(os.Stdout, os.Stderr, statePath, auditPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to initialize pdp runner: %v\n", err)
				os.Exit(int(domain.ExitInternalError))
			}
			exitCode := pdpRunner.Run(context.Background(), args[1:])
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
		Step:      "030-boot",
		Actor:     "harness-cli",
		Action:    "harness.startup",
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
