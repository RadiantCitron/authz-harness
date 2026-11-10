// Package cli 는 하네스 E2E 테스트 카탈로그를 실행하는 run 서브커맨드 러너를 제공한다.
//
// [카탈로그 실행 아키텍처 및 평가 원칙]
// 1. 다중 출력 포맷 지원 (OutputFormat):
//   - "summary": 인간 친화적 성공/실패 요약 테이블 출력.
//   - "explain": 실패한 시나리오의 단계별 상세 진단 및 원인 해설.
//   - "json": 외부 CI/CD 및 자동화 도구를 위한 완전한 기계 판독 JSON 출력.
//
// 2. 격리 실행 모드 (ExecutionMode):
//   - "subprocess": 독립 자식 프로세스를 샌드박스로 스폰하여 실제 OS 프로세스 경계를 검증 (기본 모드).
//   - "inproc": 단일 프로세스 내에서 PEP 게이트웨이를 직접 호출하여 고속 단위 테스트 수행.
//
// 3. 결정론적 종료 코드 반환:
//   - 단 1개의 시나리오라도 실패하면 ExitAuthzDenied(12)를 반환하고, 전수 통과 시 ExitSuccess(0)를 반환한다.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/harness/catalog"
	"authz-harness/internal/ui"
)

// RunConfig 는 run 서브커맨드 실행 파라미터다.
type RunConfig struct {
	ScenarioID    string // "all" 또는 "E2E-01" ~ "E2E-79" (기본값: "all")
	GroupID       string // "" 또는 "G1" ~ "G15" (기본값: "")
	ExecutionMode string // "subprocess" (기본값) 또는 "inproc"
	OutputFormat  string // "summary" (기본), "explain", "json"
	FailFast      bool   // 첫 실패 발생 시 즉시 중단 여부 (기본값: false)
	BaseDir       string // 샌드박스 생성 기준 디렉터리 (공백 시 os.MkdirTemp)
	Verbose       bool   // 상세 운영 로그 출력 여부
}

// RunRunner 는 run 서브커맨드를 조립하고 실행하는 러너다.
type RunRunner struct {
	out     io.Writer
	errOut  io.Writer
	baseDir string
}

// NewRunRunner 는 RunRunner 를 생성한다.
func NewRunRunner(out, errOut io.Writer, baseDir string) *RunRunner {
	return &RunRunner{
		out:     out,
		errOut:  errOut,
		baseDir: baseDir,
	}
}

// Run 은 CLI 인자를 파싱하고 하네스 카탈로그를 실행하여 결과를 출력한다.
func (r *RunRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var cfg RunConfig
	fs.StringVar(&cfg.ScenarioID, "scenario", "all", "실행할 시나리오 ID (all 또는 E2E-01~E2E-80)")
	fs.StringVar(&cfg.GroupID, "group", "", "실행할 시나리오 그룹 (G1~G15)")
	fs.StringVar(&cfg.ExecutionMode, "execution-mode", "subprocess", "실행 격리 모드 (subprocess | inproc)")
	fs.StringVar(&cfg.OutputFormat, "output-format", "summary", "출력 형식 (summary, explain, json)")
	fs.BoolVar(&cfg.FailFast, "fail-fast", false, "첫 실패 발생 시 즉시 중단 여부")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "상세 운영 로그 활성화")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	// 1. 출력 포맷 검증
	var formatter ui.Formatter
	switch strings.ToLower(cfg.OutputFormat) {
	case "summary", "":
		formatter = ui.NewSummaryFormatter(r.out)
	case "explain":
		formatter = ui.NewExplainFormatter(r.out)
	case "json":
		formatter = ui.NewJSONFormatter(r.out)
	default:
		fmt.Fprintf(r.errOut, "Error: invalid output format '%s' (supported: summary, explain, json)\n", cfg.OutputFormat)
		return domain.ExitBadInput
	}

	// 2. 하네스 러너 및 카탈로그 조립
	baseDir := r.baseDir
	if cfg.BaseDir != "" {
		baseDir = cfg.BaseDir
	}

	execMode := harness.ModeSubprocess
	if strings.ToLower(strings.TrimSpace(cfg.ExecutionMode)) == "inproc" {
		execMode = harness.ModeInProc
	}

	runner := harness.NewDefaultRunner(
		harness.WithBaseDir(baseDir),
		harness.WithExecutionMode(execMode),
		harness.WithEvaluator(harness.NewDefaultEvaluator()),
	)

	defer func() {
		if err := runner.Close(); err != nil {
			fmt.Fprintf(r.errOut, "Warning: failed to clean up temporary binaries: %v\n", err)
		}
	}()

	if err := catalog.RegisterAll(runner); err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to register catalog scenarios: %v\n", err)
		return domain.ExitInternalError
	}

	// 3. 실행 대상 시나리오 목록 산출
	allMetas := runner.List()
	targets := make([]string, 0)

	if cfg.ScenarioID != "" && strings.ToLower(cfg.ScenarioID) != "all" {
		// 특정 단일 시나리오 지정
		targetID := strings.ToUpper(strings.TrimSpace(cfg.ScenarioID))
		if _, ok := runner.Get(targetID); !ok {
			fmt.Fprintf(r.errOut, "Error: scenario '%s' not found in catalog\n", targetID)
			return domain.ExitBadInput
		}
		targets = append(targets, targetID)
	} else if cfg.GroupID != "" {
		// 특정 그룹 지정
		targetGroup := strings.ToUpper(strings.TrimSpace(cfg.GroupID))
		matched := false
		for _, m := range allMetas {
			if strings.ToUpper(m.Group) == targetGroup {
				targets = append(targets, m.ID)
				matched = true
			}
		}
		if !matched {
			fmt.Fprintf(r.errOut, "Error: group '%s' not found or has no scenarios\n", targetGroup)
			return domain.ExitBadInput
		}
	} else {
		// 전체 실행
		for _, m := range allMetas {
			targets = append(targets, m.ID)
		}
	}

	// 4. 시나리오 순차 실행
	results := make([]harness.ScenarioResult, 0, len(targets))
	hasFailure := false

	for _, id := range targets {
		if ctx.Err() != nil {
			fmt.Fprintf(r.errOut, "Error: run execution cancelled: %v\n", ctx.Err())
			return domain.ExitInternalError
		}

		res, err := runner.RunScenario(ctx, id)
		if err != nil {
			// 시스템 초기화 오류 등 치명적 오류
			fmt.Fprintf(r.errOut, "Error: failed to run scenario %s: %v\n", id, err)
			return domain.ExitInternalError
		}

		results = append(results, res)
		if !res.Passed && !res.Skipped {
			hasFailure = true
			if cfg.FailFast {
				break
			}
		}
	}

	// 5. 결과 포맷팅 및 출력
	if err := formatter.Format(results); err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to format output: %v\n", err)
		return domain.ExitInternalError
	}

	// 6. 표준 종료 코드 반환
	if hasFailure {
		return domain.ExitAuthzDenied // 인가/검증 실패 표준 (12)
	}

	return domain.ExitSuccess // 정상 통과 (0)
}
