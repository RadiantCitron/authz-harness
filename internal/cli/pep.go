// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(pep.go)은 인가 집행 관문(PEP: Policy Enforcement Point)을 단독 실행하고 검증하는 `pep` 서브커맨드 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. 단일 집행 관문 (Unified PEP Gateway):
//    - read: 토큰 기반 파일 읽기 인가 및 격리 워크스페이스 내 도구 실행.
//    - write: 토큰 기반 파일 쓰기 인가 (텍스트 인자 또는 --data-file 파일 읽기 주입 지원).
// 2. Zone B 격리 원칙 (Zone B Confinement):
//    - app.BuildStack 호출 시 VerifyOnly: true 를 지정하여 서명용 개인키가 존재하는 Zone A에 일체 접근하지 않고,
//      Zone B의 공개 검증 키(JWKS), 상태 파일, Replay 원장, 감사 로그만을 사용하여 검증한다.
// 3. 파이프라인 단계별 시각화 (11-Stage Pipeline Box Visualization):
//    - domain.PEPStages() 의 각 단계(인증, 재생, 에포크, 스코프, PDP 인가, 승인, 도구 바인딩, 경계 검증, 예산, 사전 감사, 집행)를
//      [PASS], [FAIL], [SKIPPED], [N/A] 상태로 ASCII 박스에 명확히 매핑하여 출력한다.
// 4. 보안 가드레일:
//    - parseNonNegativeClockOffset: 클록 오프셋에 음수를 허용하지 않아 이미 만료된 토큰이 과거 시간으로 부활하는 보안 취약점을 차단한다.
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
// 인가 집행 관문(pep.Gateway)을 초기화하여 요청을 파이프라인에 통과시키고, 그 결과를 렌더링한다.
type PEPRunner struct {
	out          io.Writer // 표준 출력 스트림
	errOut       io.Writer // 표준 에러 스트림
	workspaceDir string    // 격리된 워크스페이스 루트 경로
	auditPath    string    // 감사 로그 파일 경로
	statePath    string    // 상태 저장 파일 경로
	pubJWKSPath  string    // Zone B 공개 검증 키(JWKS) 경로
	replayPath   string    // Replay 방지 원장 파일 경로
}

// NewPEPRunner 는 파일 경로들을 받아 의존성을 조립하고 PEPRunner를 생성한다.
func NewPEPRunner(
	out, errOut io.Writer,
	workspaceDir, statePath, pubJWKSPath, replayPath, auditPath string,
) (*PEPRunner, error) {
	return &PEPRunner{
		out:          out,
		errOut:       errOut,
		workspaceDir: workspaceDir,
		auditPath:    auditPath,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
	}, nil
}

// Run 은 주어진 인자에 따라 `read` 또는 `write` 서브커맨드를 라우팅 실행한다.
// 실행 시 VerifyOnly: true 스택을 구성하여 Zone A(개인키) 미접근 원칙을 준수한다.
func (r *PEPRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	stack, err := app.BuildStack(app.AppConfig{
		WorkspaceDir: r.workspaceDir,
		StatePath:    r.statePath,
		PubJWKSPath:  r.pubJWKSPath,
		ReplayPath:   r.replayPath,
		AuditPath:    r.auditPath,
		VerifyOnly:   true, // PEP CLI 는 검증 전용(Zone A 개인키 미접근)
	})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to initialize pep runner: %v\n", err)
		return domain.ExitInternalError
	}
	defer stack.Close()

	if len(args) == 0 {
		fmt.Fprintf(r.errOut, "Error: missing pep subcommand (expected 'read' or 'write')\n")
		return domain.ExitBadInput
	}

	subcmd := args[0]
	switch subcmd {
	case "read":
		return r.runRead(ctx, stack.PEP, args[1:])
	case "write":
		return r.runWrite(ctx, stack.PEP, args[1:])
	default:
		fmt.Fprintf(r.errOut, "Error: unknown pep subcommand '%s'\n", subcmd)
		return domain.ExitBadInput
	}
}

// pepCommonFlags 는 read/write 서브커맨드가 공유하는 공통 플래그 모음이다.
type pepCommonFlags struct {
	tokenStr           string // 제시된 Bearer Access Token 문자열
	expectedAud        string // 기대하는 대상 오디언스 (Audience)
	expectedSub        string // 기대하는 주체 (Subject, 선택)
	clockOffsetStr     string // 가상 시계 시간 오프셋 (테스트용)
	injectAuditFailure bool   // 감사 실패 시 Fail-Closed 거부 동작 주입 여부
	outputFormat       string // 출력 형식 ("text" 또는 "json")
	traceID            string // 트랜잭션 추적 식별자
}

// parseCommonPEPFlags 는 FlagSet 에 PEP 공통 플래그들을 바인딩한다.
func (r *PEPRunner) parseCommonPEPFlags(fs *flag.FlagSet, c *pepCommonFlags) {
	fs.StringVar(&c.tokenStr, "token", "", "RFC 9068 Bearer Access Token (required)")
	fs.StringVar(&c.expectedAud, "expected-aud", "authz-harness", "Expected token audience")
	fs.StringVar(&c.expectedSub, "expected-sub", "", "Expected token subject (optional)")
	fs.StringVar(&c.clockOffsetStr, "clock-offset", "", "Clock offset duration (e.g. 10m)")
	fs.BoolVar(&c.injectAuditFailure, "inject-audit-failure", false, "Simulate fail-closed audit write failure")
	fs.StringVar(&c.outputFormat, "output-format", "text", "Output format: text or json")
	fs.StringVar(&c.traceID, "trace-id", "", "Explicit transaction trace ID")
}

// executePEPAction 은 공통 인자를 검증하고 pep.Gateway.Execute 를 호출하여 파이프라인을 구동한다.
func (r *PEPRunner) executePEPAction(ctx context.Context, gateway pep.Gateway, action domain.Action, actionName string, c pepCommonFlags, resource string, data []byte) domain.ExitCode {
	if strings.TrimSpace(resource) == "" {
		fmt.Fprintf(r.errOut, "Error: missing resource path for %s\n", actionName)
		return domain.ExitBadInput
	}

	if strings.TrimSpace(c.tokenStr) == "" {
		fmt.Fprintf(r.errOut, "Error: missing required --token flag\n")
		return domain.ExitBadInput
	}

	clockOffset, err := parseNonNegativeClockOffset(c.clockOffsetStr)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: %v\n", err)
		return domain.ExitBadInput
	}

	traceID := c.traceID
	if traceID == "" {
		traceID = fmt.Sprintf("pep-%s-%d", actionName, time.Now().UnixNano())
	}

	req := pep.Request{
		Token:              c.tokenStr,
		Action:             action,
		Resource:           resource,
		Data:               data,
		InjectAuditFailure: c.injectAuditFailure,
		ExpectedAudience:   c.expectedAud,
		ExpectedSubject:    c.expectedSub,
		ClockOffset:        clockOffset,
		TraceID:            traceID,
	}

	res, err := gateway.Execute(ctx, req)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: internal error executing pep %s: %v\n", actionName, err)
		return domain.ExitInternalError
	}

	r.renderResult(req, res, c.outputFormat)
	return res.ExitCode
}

// runRead 는 파일 읽기(file:read) 요청을 인가 집행 관문에 전달한다.
func (r *PEPRunner) runRead(ctx context.Context, gateway pep.Gateway, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("pep read", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var c pepCommonFlags
	r.parseCommonPEPFlags(fs, &c)

	resource, flagArgs := splitPEPResourceAndFlags(args)
	if err := fs.Parse(flagArgs); err != nil {
		return domain.ExitBadInput
	}
	if strings.TrimSpace(resource) == "" && fs.NArg() > 0 {
		resource = fs.Arg(0)
	}

	return r.executePEPAction(ctx, gateway, domain.ActionFileRead, "read", c, resource, nil)
}

// runWrite 는 파일 쓰기(file:write) 요청을 인가 집행 관문에 전달한다.
func (r *PEPRunner) runWrite(ctx context.Context, gateway pep.Gateway, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("pep write", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var (
		c        pepCommonFlags
		dataStr  string
		dataFile string
	)
	r.parseCommonPEPFlags(fs, &c)
	fs.StringVar(&dataStr, "data", "", "Text content to write")
	fs.StringVar(&dataFile, "data-file", "", "File path containing content to write")

	resource, flagArgs := splitPEPResourceAndFlags(args)
	if err := fs.Parse(flagArgs); err != nil {
		return domain.ExitBadInput
	}
	if strings.TrimSpace(resource) == "" && fs.NArg() > 0 {
		resource = fs.Arg(0)
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

	return r.executePEPAction(ctx, gateway, domain.ActionFileWrite, "write", c, resource, writeBytes)
}

// renderResult 는 실행 결과를 JSON 또는 ASCII 파이프라인 박스 형태로 포맷팅하여 출력한다.
func (r *PEPRunner) renderResult(req pep.Request, res *pep.Result, format string) {
	if strings.ToLower(strings.TrimSpace(format)) == "json" {
		type jsonOutput struct {
			TraceID    string          `json:"trace_id"`
			Action     string          `json:"action"`
			Resource   string          `json:"resource"`
			Allowed    bool            `json:"allowed"`
			ExitCode   domain.ExitCode `json:"exit_code"`
			Stage      domain.Stage    `json:"failed_stage,omitempty"`
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
		if err := enc.Encode(outObj); err != nil {
			fmt.Fprintf(r.errOut, "Error: failed to encode json output: %v\n", err)
		}
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

// 화면 칸 상태 상수. 단계 순서·통과 여부는 CLI 가 임의 추론하지 않고 pep 가 남긴 사실(pep.Stages, Result.Passed)을 읽는다.
const (
	boxPass    = "[PASS]"
	boxFail    = "[FAIL]"
	boxSkipped = "[SKIPPED]" // 앞 단계 실패로 도달하지 못함
	boxNA      = "[N/A]"     // 이 요청에는 해당 없는 조건부 단계(승인·예산 등)
)

// stageBox 는 화면에 렌더링될 단일 파이프라인 단계 칸이다.
type stageBox struct {
	Label  string // 단계 레이블 명칭
	Status string // 박스 상태 ([PASS], [FAIL], [SKIPPED], [N/A])
	Info   string // 부가 정보 문자열
}

// stageBoxes 는 pep.Stages() 의 모든 단계에 대해 칸을 만든다. 상태 규칙:
// 통과 기록에 있으면 PASS, 거부된 단계면 FAIL, 실패 단계보다 뒤면 SKIPPED, 그 밖은 N/A.
// 라벨이 없는 단계도 단계 문자열로 그려 칸이 조용히 사라지지 않게 한다.
// 거부 결과의 실패 단계가 정식 목록에 없으면 목록 아래에 FAIL 칸을 하나 더 붙인다.
func stageBoxes(res *pep.Result) []stageBox {
	passed := make(map[domain.Stage]bool, len(res.Passed))
	for _, s := range res.Passed {
		passed[s] = true
	}

	stages := domain.PEPStages()
	failedIdx := -1
	for i, s := range stages {
		if !res.Allowed && s.ID == res.Stage {
			failedIdx = i
		}
	}

	boxes := make([]stageBox, 0, len(stages)+1)
	for i, s := range stages {
		box := stageBox{Label: s.Label}
		switch {
		case passed[s.ID]:
			box.Status, box.Info = boxPass, stagePassInfo(s.ID, res)
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

// stagePassInfo 는 통과한 단계 칸에 붙는 부가 상세 정보를 생성한다.
func stagePassInfo(s domain.Stage, res *pep.Result) string {
	switch s {
	case domain.StageAuthn:
		return fmt.Sprintf("(Sub: %s, JTI: %s)", res.Subject, res.TokenJTI)
	case domain.StageAuthz:
		if res.Allowed {
			return "(PDP Grant Validated)"
		}
		return "(Grant Validated)"
	case domain.StageBoundary:
		return fmt.Sprintf("(SafePath: %s)", res.SafePath)
	case domain.StagePrecommitAudit:
		if res.Allowed {
			return "(Pre-Commit Audit Recorded)"
		}
		return "(Audit Recorded)"
	case domain.StageExecute:
		if res.BytesWrote > 0 {
			return fmt.Sprintf("(Wrote %d bytes)", res.BytesWrote)
		}
		return fmt.Sprintf("(Read %d bytes)", res.BytesRead)
	}
	return ""
}

// renderStageBoxes 는 단계 칸들을 순서대로 stdout 에 출력한다.
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
// args 에서 위치 인자(resource)와 플래그(값 포함)를 안전하게 분리한다.
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
