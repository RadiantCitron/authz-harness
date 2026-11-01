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

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
	"authz-harness/internal/jail"
)

// PEPRunner 는 `pep` 하위 명령어(read, write) 실행을 주관하는 CLI 러너다.
type PEPRunner struct {
	gateway      pep.Gateway
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
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to prepare workspace dir: %w", err)
	}

	workspaceJail, err := jail.New(workspaceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to init workspace jail: %w", err)
	}

	stateStore, err := state.NewFileStore(statePath)
	if err != nil {
		return nil, fmt.Errorf("failed to init state store: %w", err)
	}

	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init audit writer: %w", err)
	}

	pipSvc := pip.NewService(stateStore)
	pdpSvc := pdp.NewService(pipSvc, auditWriter)

	keyStore, err := keys.NewFileStore("", pubJWKSPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init keys store: %w", err)
	}

	keyMgr, err := keys.NewManager(keyStore, auditWriter)
	if err != nil {
		return nil, fmt.Errorf("failed to init keys manager: %w", err)
	}

	clock := domain.RealClock{}
	replayLedger, err := token.NewFileReplayLedger(replayPath, clock)
	if err != nil {
		return nil, fmt.Errorf("failed to init replay ledger: %w", err)
	}

	tokenVerifier := token.NewVerifier(keyMgr, replayLedger, auditWriter, clock)

	gw, err := pep.NewGateway(pep.Config{
		Verifier:    tokenVerifier,
		PDP:         pdpSvc,
		Jail:        workspaceJail,
		AuditWriter: auditWriter,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init pep gateway: %w", err)
	}

	return &PEPRunner{
		gateway:      gw,
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
	var flagArgs []string
	var resource string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			// 플래그에 값이 오는 경우 (--flag val)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				// bool 플래그인 --inject-audit-failure 제외
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

	var clockOffset time.Duration
	if strings.TrimSpace(clockOffsetStr) != "" {
		parsed, err := time.ParseDuration(clockOffsetStr)
		if err != nil {
			fmt.Fprintf(r.errOut, "Error: invalid --clock-offset: %v\n", err)
			return domain.ExitBadInput
		}
		clockOffset = parsed
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

	res, err := r.gateway.Execute(ctx, req)
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

	var flagArgs []string
	var resource string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
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

	var clockOffset time.Duration
	if strings.TrimSpace(clockOffsetStr) != "" {
		parsed, err := time.ParseDuration(clockOffsetStr)
		if err != nil {
			fmt.Fprintf(r.errOut, "Error: invalid --clock-offset: %v\n", err)
			return domain.ExitBadInput
		}
		clockOffset = parsed
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

	res, err := r.gateway.Execute(ctx, req)
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

	g1Status, g1Info := stageBoxStatus(pep.StageGate1AuthN, res)
	g2Status, g2Info := stageBoxStatus(pep.StageGate2AuthZ, res)
	g2cStatus, g2cInfo := stageBoxStatus(pep.StageGate2cJail, res)
	s4Status, s4Info := stageBoxStatus(pep.Stage4Audit, res)
	s5Status, s5Info := stageBoxStatus(pep.Stage5FileIO, res)

	fmt.Fprintf(r.out, "[Gate 1] AuthN Token Verification   : %s %s\n", g1Status, g1Info)
	fmt.Fprintf(r.out, "[Gate 2] Pure PDP Authorization     : %s %s\n", g2Status, g2Info)
	fmt.Fprintf(r.out, "[Gate 2c] Workspace Jail Boundary   : %s %s\n", g2cStatus, g2cInfo)
	fmt.Fprintf(r.out, "[Stage 4] Pre-Commit Audit Flush    : %s %s\n", s4Status, s4Info)
	fmt.Fprintf(r.out, "[Stage 5] Confined File I/O         : %s %s\n", s5Status, s5Info)
	fmt.Fprintf(r.out, "---------------------------------------------------------\n")

	decisionStr := "DENY"
	if res.Allowed {
		decisionStr = "ALLOW"
	}
	fmt.Fprintf(r.out, "DECISION: %s | EXIT CODE: %d (%s)\n", decisionStr, res.ExitCode, exitCodeName(res.ExitCode))
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

func stageBoxStatus(targetStage pep.Stage, res *pep.Result) (string, string) {
	stageOrder := map[pep.Stage]int{
		pep.StageGate0Input: 0,
		pep.StageGate1AuthN: 1,
		pep.StageGate2AuthZ: 2,
		pep.StageGate2cJail: 3,
		pep.Stage4Audit:     4,
		pep.Stage5FileIO:    5,
	}

	targetIdx := stageOrder[targetStage]

	if res.Allowed {
		switch targetStage {
		case pep.StageGate1AuthN:
			return "[PASS]", fmt.Sprintf("(Sub: %s, JTI: %s)", res.Subject, res.TokenJTI)
		case pep.StageGate2AuthZ:
			return "[PASS]", "(PDP Grant Validated)"
		case pep.StageGate2cJail:
			return "[PASS]", fmt.Sprintf("(SafePath: %s)", res.SafePath)
		case pep.Stage4Audit:
			return "[PASS]", "(Pre-Commit Audit Recorded)"
		case pep.Stage5FileIO:
			if res.BytesWrote > 0 {
				return "[PASS]", fmt.Sprintf("(Wrote %d bytes)", res.BytesWrote)
			}
			return "[PASS]", fmt.Sprintf("(Read %d bytes)", res.BytesRead)
		}
		return "[PASS]", ""
	}

	failedIdx := stageOrder[res.Stage]
	if targetIdx < failedIdx {
		switch targetStage {
		case pep.StageGate1AuthN:
			return "[PASS]", fmt.Sprintf("(Sub: %s, JTI: %s)", res.Subject, res.TokenJTI)
		case pep.StageGate2AuthZ:
			return "[PASS]", "(Grant Validated)"
		case pep.StageGate2cJail:
			return "[PASS]", fmt.Sprintf("(SafePath: %s)", res.SafePath)
		case pep.Stage4Audit:
			return "[PASS]", "(Audit Recorded)"
		}
		return "[PASS]", ""
	}

	if targetIdx == failedIdx {
		return "[FAIL]", fmt.Sprintf("(%s)", res.Reason)
	}

	return "[SKIPPED]", ""
}

func exitCodeName(c domain.ExitCode) string {
	switch c {
	case domain.ExitSuccess:
		return "ExitSuccess"
	case domain.ExitTokenInvalid:
		return "ExitTokenInvalid"
	case domain.ExitAuthzDenied:
		return "ExitAuthzDenied"
	case domain.ExitPathViolation:
		return "ExitPathViolation"
	case domain.ExitBadInput:
		return "ExitBadInput"
	case domain.ExitAuditFailure:
		return "ExitAuditFailure"
	case domain.ExitInternalError:
		return "ExitInternalError"
	default:
		return "Unknown"
	}
}
