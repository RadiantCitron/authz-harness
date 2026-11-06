package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// PEPRunner 는 `pep` 하위 명령어(read, write) 실행을 주관하는 CLI 러너다.
type PEPRunner struct {
	stack        *app.AppStack
	out          io.Writer
	errOut       io.Writer
	workspaceDir string
	auditPath    string
	statePath    string
	pubJWKSPath  string
	replayPath   string
}

// NewPEPRunner 는 파일 경로들을 받아 의존성을 조립하고 PEPRunner를 생성한다.
func NewPEPRunner(
	out, errOut io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
) (*PEPRunner, error) {
	stack, err := app.BuildStack(app.AppConfig{
		WorkspaceDir: workspaceDir,
		StatePath:    statePath,
		PubJWKSPath:  pubJWKSPath,
		ReplayPath:   replayPath,
		AuditPath:    auditPath,
		VerifyOnly:   true, // PEP CLI 는 검증 전용(Zone A 개인키 미접근)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pep stack: %w", err)
	}

	return &PEPRunner{
		stack:        stack,
		out:          out,
		errOut:       errOut,
		workspaceDir: workspaceDir,
		auditPath:    auditPath,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
	}, nil
}

// Close 는 PEPRunner 내부 스택(AuditWriter 등) 리소스를 정리한다.
func (r *PEPRunner) Close() error {
	if r.stack != nil {
		return r.stack.Close()
	}
	return nil
}

// Run 은 주어진 인자에 따라 `read` 또는 `write` 서브커맨드를 라우팅 실행한다.
func (r *PEPRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: missing pep subcommand (expected 'read' or 'write')\n")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	switch subcmd {
	case "read":
		return r.runRead(ctx, args[1:])
	case "write":
		return r.runWrite(ctx, args[1:])
	default:
		fmt.Fprintf(r.errOut, "Error: unknown pep subcommand '%s'\n", subcmd)
		return domain.ExitBadInput
	}
}

func (r *PEPRunner) runRead(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("pep read", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var (
		tokenStr           string
		expectedAud        string
		expectedSub        string
		clockOffsetStr     string
		injectAuditFailure bool
		outputFormat       string
		traceID            string
	)

	fs.StringVar(&tokenStr, "token", "", "RFC 9068 Bearer Access Token (required)")
	fs.StringVar(&expectedAud, "expected-aud", "authz-harness", "Expected token audience")
	fs.StringVar(&expectedSub, "expected-sub", "", "Expected token subject (optional)")
	fs.StringVar(&clockOffsetStr, "clock-offset", "", "Clock offset duration (e.g. 10m)")
	fs.BoolVar(&injectAuditFailure, "inject-audit-failure", false, "Simulate fail-closed audit write failure")
	fs.StringVar(&outputFormat, "output-format", "text", "Output format: text or json")
	fs.StringVar(&traceID, "trace-id", "", "Explicit transaction trace ID")

	// flag.FlagSet 은 non-flag 인자(resource)를 만나면 파싱을 중단하므로,
	// args 에서 플래그와 resource 경로를 분리하거나 맨 뒤/앞의 resource를 식별한다.
	resource, flagArgs := splitPEPResourceAndFlags(args)

	if err := fs.Parse(flagArgs); err != nil {
		return domain.ExitBadInput
	}

	if strings.TrimSpace(resource) == "" && fs.NArg() > 0 {
		resource = fs.Arg(0)
	}

	if strings.TrimSpace(resource) == "" {
		fmt.Fprintf(r.errOut, "Error: missing resource path for read\n")
		return domain.ExitBadInput
	}

	if strings.TrimSpace(tokenStr) == "" {
		fmt.Fprintf(r.errOut, "Error: missing required --token flag\n")
		return domain.ExitBadInput
	}

	clockOffset, err := parseNonNegativeClockOffset(clockOffsetStr)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitBadInput
	}

	if traceID == "" {
		traceID = fmt.Sprintf("pep-read-%d", time.Now().UnixNano())
	}

	req := pep.Request{
		Token:              tokenStr,
		Action:             domain.ActionFileRead,
		Resource:           resource,
		InjectAuditFailure: injectAuditFailure,
		ExpectedAudience:   expectedAud,
		ExpectedSubject:    expectedSub,
		ClockOffset:        clockOffset,
		TraceID:            traceID,
	}

	res, err := r.stack.PEP.Execute(ctx, req)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: internal error executing pep read: %v\n", err)
		return domain.ExitInternalError
	}

	r.renderResult(req, res, outputFormat)
	return res.ExitCode
}

func (r *PEPRunner) runWrite(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("pep write", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var (
		tokenStr           string
		dataStr            string
		dataFile           string
		expectedAud        string
		expectedSub        string
		clockOffsetStr     string
		injectAuditFailure bool
		outputFormat       string
		traceID            string
	)

	fs.StringVar(&tokenStr, "token", "", "RFC 9068 Bearer Access Token (required)")
	fs.StringVar(&dataStr, "data", "", "Text content to write")
	fs.StringVar(&dataFile, "data-file", "", "File path containing content to write")
	fs.StringVar(&expectedAud, "expected-aud", "authz-harness", "Expected token audience")
	fs.StringVar(&expectedSub, "expected-sub", "", "Expected token subject (optional)")
	fs.StringVar(&clockOffsetStr, "clock-offset", "", "Clock offset duration (e.g. 10m)")
	fs.BoolVar(&injectAuditFailure, "inject-audit-failure", false, "Simulate fail-closed audit write failure")
	fs.StringVar(&outputFormat, "output-format", "text", "Output format: text or json")
	fs.StringVar(&traceID, "trace-id", "", "Explicit transaction trace ID")

	resource, flagArgs := splitPEPResourceAndFlags(args)

	if err := fs.Parse(flagArgs); err != nil {
		return domain.ExitBadInput
	}

	if strings.TrimSpace(resource) == "" && fs.NArg() > 0 {
		resource = fs.Arg(0)
	}

	if strings.TrimSpace(resource) == "" {
		fmt.Fprintf(r.errOut, "Error: missing resource path for write\n")
		return domain.ExitBadInput
	}

	if strings.TrimSpace(tokenStr) == "" {
		fmt.Fprintf(r.errOut, "Error: missing required --token flag\n")
		return domain.ExitBadInput
	}

	var writeBytes []byte
	if dataFile != "" {
		content, err := os.ReadFile(dataFile)
		if err != nil {
			fmt.Fprintf(r.errOut, "Error: failed to read --data-file: %v\n", err)
			return domain.ExitBadInput
		}
		writeBytes = content
	} else {
		writeBytes = []byte(dataStr)
	}

	clockOffset, err := parseNonNegativeClockOffset(clockOffsetStr)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitBadInput
	}

	if traceID == "" {
		traceID = fmt.Sprintf("pep-write-%d", time.Now().UnixNano())
	}

	req := pep.Request{
		Token:              tokenStr,
		Action:             domain.ActionFileWrite,
		Resource:           resource,
		Data:               writeBytes,
		InjectAuditFailure: injectAuditFailure,
		ExpectedAudience:   expectedAud,
		ExpectedSubject:    expectedSub,
		ClockOffset:        clockOffset,
		TraceID:            traceID,
	}

	res, err := r.stack.PEP.Execute(ctx, req)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: internal error executing pep write: %v\n", err)
		return domain.ExitInternalError
	}

	r.renderResult(req, res, outputFormat)
	return res.ExitCode
}

func (r *PEPRunner) renderResult(req pep.Request, res *pep.Result, format string) {
	if strings.ToLower(strings.TrimSpace(format)) == "json" {
		type jsonOutput struct {
			TraceID    string          `json:"trace_id"`
			Action     string          `json:"action"`
			Resource   string          `json:"resource"`
			Allowed    bool            `json:"allowed"`
			ExitCode   domain.ExitCode `json:"exit_code"`
			Stage      pep.Stage       `json:"failed_stage,omitempty"`
			Reason     domain.Reason   `json:"reason"`
			Details    string          `json:"details,omitempty"`
			Subject    string          `json:"subject,omitempty"`
			TokenJTI   string          `json:"token_jti,omitempty"`
			SafePath   string          `json:"safe_path,omitempty"`
			BytesRead  int             `json:"bytes_read,omitempty"`
			BytesWrote int             `json:"bytes_wrote,omitempty"`
			Content    string          `json:"content,omitempty"`
		}

		outObj := jsonOutput{
			TraceID:    req.TraceID,
			Action:     string(req.Action),
			Resource:   req.Resource,
			Allowed:    res.Allowed,
			ExitCode:   res.ExitCode,
			Stage:      res.Stage,
			Reason:     res.Reason,
			Details:    res.Details,
			Subject:    res.Subject,
			TokenJTI:   res.TokenJTI,
			SafePath:   res.SafePath,
			BytesRead:  res.BytesRead,
			BytesWrote: res.BytesWrote,
		}
		if len(res.Data) > 0 {
			outObj.Content = string(res.Data)
		}

		enc := json.NewEncoder(r.out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(outObj)
		return
	}

	// ASCII 박스 뷰 렌더링
	fmt.Fprintf(r.out, "=== PEP Pipeline Execution [TraceID: %s] ===\n", req.TraceID)
	fmt.Fprintf(r.out, "Action: %s | Resource: %s\n", req.Action, req.Resource)

	renderStageBoxes(r.out, res)
	fmt.Fprintf(r.out, "---------------------------------------------------------\n")

	decisionStr := "DENY"
	if res.Allowed {
		decisionStr = "ALLOW"
	}
	fmt.Fprintf(r.out, "DECISION: %s | EXIT CODE: %d (%s)\n", decisionStr, res.ExitCode, domain.ExitCodeName(res.ExitCode))
	if !res.Allowed {
		fmt.Fprintf(r.out, "Reason: %s: %s\n", res.Reason, res.Details)
	}
	fmt.Fprintf(r.out, "=========================================================\n")

	if res.Allowed && req.Action == domain.ActionFileRead && len(res.Data) > 0 {
		fmt.Fprintf(r.out, "--- File Content ---\n")
		r.out.Write(res.Data)
		if !strings.HasSuffix(string(res.Data), "\n") {
			fmt.Fprintln(r.out)
		}
	}
}

// 화면 칸 상태. 단계 순서·통과 여부는 CLI 가 추론하지 않고 pep 가 남긴 사실(pep.Stages, Result.Passed)을 읽는다.
const (
	boxPass    = "[PASS]"
	boxFail    = "[FAIL]"
	boxSkipped = "[SKIPPED]" // 앞 단계 실패로 도달하지 못함
	boxNA      = "[N/A]"     // 이 요청에는 해당 없는 조건부 단계(승인·예산 등)
)

// stageLabels 는 단계별 화면 문구다. 표시 문구는 표시 계층의 일이라 여기 두되,
// pep.Stages() 의 모든 단계가 라벨을 갖는지는 시험(TestStageLabels_CoverEveryStage)이 강제한다.
var stageLabels = map[pep.Stage]string{
	pep.StageGate0Input: "[Gate 0] Input Validation",
	pep.StageGate1AuthN: "[Gate 1] AuthN Token Verification",
	pep.StageGate2AuthZ: "[Gate 2] Pure PDP Authorization",
	pep.StageReplay:     "[Gate 2b] jti Replay Consume",
	pep.StageGate2cJail: "[Gate 2c] Workspace Jail Boundary",
	pep.StageApproval:   "[Stage 3a] Human Approval Consume",
	pep.StageBudget:     "[Stage 3b] Budget Pre-Charge",
	pep.Stage4Audit:     "[Stage 4] Pre-Commit Audit Flush",
	pep.Stage5FileIO:    "[Stage 5] Confined File I/O",
}

// stageBox 는 화면의 한 칸이다.
type stageBox struct {
	Label  string
	Status string
	Info   string
}

// stageBoxes 는 pep.Stages() 의 모든 단계에 대해 칸을 만든다. 상태 규칙:
// 통과 기록에 있으면 PASS, 거부된 단계면 FAIL, 실패 단계보다 뒤면 SKIPPED, 그 밖은 N/A.
// 라벨이 없는 단계도 단계 문자열로 그려 칸이 조용히 사라지지 않게 한다.
// 거부 결과의 실패 단계가 정식 목록에 없으면 목록 아래에 FAIL 칸을 하나 더 붙인다.
func stageBoxes(res *pep.Result) []stageBox {
	passed := make(map[pep.Stage]bool, len(res.Passed))
	for _, s := range res.Passed {
		passed[s] = true
	}

	stages := pep.Stages()
	failedIdx := -1
	for i, s := range stages {
		if !res.Allowed && s == res.Stage {
			failedIdx = i
		}
	}

	boxes := make([]stageBox, 0, len(stages)+1)
	for i, s := range stages {
		label, ok := stageLabels[s]
		if !ok {
			label = string(s)
		}
		box := stageBox{Label: label}
		switch {
		case passed[s]:
			box.Status, box.Info = boxPass, stagePassInfo(s, res)
		case !res.Allowed && i == failedIdx:
			box.Status, box.Info = boxFail, fmt.Sprintf("(%s)", res.Reason)
		case failedIdx >= 0 && i > failedIdx:
			box.Status = boxSkipped
		default:
			box.Status, box.Info = boxNA, "(not applicable)"
		}
		boxes = append(boxes, box)
	}

	if !res.Allowed && failedIdx < 0 {
		boxes = append(boxes, stageBox{
			Label:  fmt.Sprintf("[?] unknown stage %q", string(res.Stage)),
			Status: boxFail,
			Info:   fmt.Sprintf("(%s)", res.Reason),
		})
	}
	return boxes
}

// stagePassInfo 는 통과한 칸에 붙는 부가 정보다.
func stagePassInfo(s pep.Stage, res *pep.Result) string {
	switch s {
	case pep.StageGate1AuthN:
		return fmt.Sprintf("(Sub: %s, JTI: %s)", res.Subject, res.TokenJTI)
	case pep.StageGate2AuthZ:
		if res.Allowed {
			return "(PDP Grant Validated)"
		}
		return "(Grant Validated)"
	case pep.StageGate2cJail:
		return fmt.Sprintf("(SafePath: %s)", res.SafePath)
	case pep.Stage4Audit:
		if res.Allowed {
			return "(Pre-Commit Audit Recorded)"
		}
		return "(Audit Recorded)"
	case pep.Stage5FileIO:
		if res.BytesWrote > 0 {
			return fmt.Sprintf("(Wrote %d bytes)", res.BytesWrote)
		}
		return fmt.Sprintf("(Read %d bytes)", res.BytesRead)
	}
	return ""
}

// renderStageBoxes 는 단계 칸을 한 줄씩 출력한다.
func renderStageBoxes(w io.Writer, res *pep.Result) {
	for _, b := range stageBoxes(res) {
		line := fmt.Sprintf("%-36s: %s", b.Label, b.Status)
		if b.Info != "" {
			line += " " + b.Info
		}
		fmt.Fprintln(w, line)
	}
}

// splitPEPResourceAndFlags 는 flag.FlagSet 이 non-flag 인자를 만나면 파싱을 중단하는 제약 때문에,
// args 에서 위치 인자(resource)와 플래그(값 포함)를 분리한다.
func splitPEPResourceAndFlags(args []string) (resource string, flagArgs []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			// 플래그에 값이 오는 경우 (--flag val). bool 플래그 --inject-audit-failure 는 제외.
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if arg != "-inject-audit-failure" && arg != "--inject-audit-failure" {
					flagArgs = append(flagArgs, args[i+1])
					i++
				}
			}
		} else if resource == "" {
			resource = arg
		} else {
			flagArgs = append(flagArgs, arg)
		}
	}
	return resource, flagArgs
}

// parseNonNegativeClockOffset 은 --clock-offset 값을 파싱하며 빈 값은 0, 음수는 거부한다(만료 토큰 부활 방지).
func parseNonNegativeClockOffset(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid --clock-offset: %w", err)
	}
	if d < 0 {
		return 0, fmt.Errorf("--clock-offset must not be negative (만료 토큰 부활 방지)")
	}
	return d, nil
}
