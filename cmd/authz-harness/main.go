package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/cli"
)

const Version = "0.1.0"

func main() {
	var (
		showVersion bool
		auditPath   string
		verbose     bool
	)

	flag.BoolVar(&showVersion, "version", false, "프로그램 버전 출력")
	flag.StringVar(&auditPath, "audit-file", "audit.jsonl", "감사 로그 저장 파일 경로")
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
		os.Exit(0)
	}

	logger.Debug("authz-harness starting", "version", Version, "audit_file", auditPath)

	// 3. 감사 로그 (Audit Writer) 초기화 및 시동 확인
	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize audit writer: %v\n", err)
		os.Exit(1)
	}
	defer auditWriter.Close()

	// 스모크 테스트용 초기 감사 이벤트 1건 기록
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
		os.Exit(1)
	}

	formatter.PrintBanner(Version)
	fmt.Println("CLI 및 감사/운영로그 3중 배선 골격이 정상 작동 중입니다.")
	fmt.Printf("감사 로그 저장 위치: %s\n", auditPath)
}
