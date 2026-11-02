package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
	"authz-harness/internal/ui"
)

// AuditRunner 는 `audit` 하위 명령어(timeline, verify)를 주관하는 러너다.
type AuditRunner struct {
	out       io.Writer
	errOut    io.Writer
	auditPath string
}

// NewAuditRunner 는 AuditRunner 인스턴스를 생성한다.
func NewAuditRunner(out, errOut io.Writer, auditPath string) *AuditRunner {
	return &AuditRunner{
		out:       out,
		errOut:    errOut,
		auditPath: auditPath,
	}
}

// Run 은 audit 하위 명령어를 파싱하고 실행한다.
func (r *AuditRunner) Run(ctx context.Context, args []string) domain.ExitCode {
	if len(args) == 0 {
		r.printUsage()
		return domain.ExitBadInput
	}

	subcmd := args[0]
	switch subcmd {
	case "timeline":
		return r.runTimeline(ctx, args[1:])
	case "verify":
		return r.runVerify(ctx, args[1:])
	default:
		fmt.Fprintf(r.errOut, "Error: unknown audit command '%s'\n", subcmd)
		r.printUsage()
		return domain.ExitBadInput
	}
}

func (r *AuditRunner) runTimeline(ctx context.Context, args []string) domain.ExitCode {
	fs := flag.NewFlagSet("audit timeline", flag.ContinueOnError)
	fs.SetOutput(r.errOut)

	var (
		traceID string
		latest  bool
	)

	fs.StringVar(&traceID, "trace-id", "", "시각화할 분산 추적 식별자 (TraceID)")
	fs.BoolVar(&latest, "latest", false, "가장 최근 기록된 TraceID 시각화")

	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	f, err := os.Open(r.auditPath)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to open audit file '%s': %v\n", r.auditPath, err)
		return domain.ExitAuditFailure
	}
	defer f.Close()

	var allEvents []audit.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			allEvents = append(allEvents, ev)
		}
	}

	if len(allEvents) == 0 {
		fmt.Fprintf(r.errOut, "Error: no audit events found in %s\n", r.auditPath)
		return domain.ExitAuditFailure
	}

	targetTraceID := strings.TrimSpace(traceID)
	if latest || targetTraceID == "" {
		if latest || targetTraceID == "" {
			// 가장 최근 이벤트의 TraceID 탐색
			for i := len(allEvents) - 1; i >= 0; i-- {
				if allEvents[i].TraceID != "" {
					targetTraceID = allEvents[i].TraceID
					break
				}
			}
		}
	}

	if targetTraceID == "" {
		fmt.Fprintf(r.errOut, "Error: --trace-id is required or no valid trace found\n")
		return domain.ExitBadInput
	}

	// targetTraceID 에 해당하는 이벤트 필터링
	var matchedEvents []audit.Event
	for _, ev := range allEvents {
		if ev.TraceID == targetTraceID {
			matchedEvents = append(matchedEvents, ev)
		}
	}

	if len(matchedEvents) == 0 {
		fmt.Fprintf(r.errOut, "Error: no audit events found for trace ID '%s'\n", targetTraceID)
		return domain.ExitBadInput
	}

	// 해시 체인 무결성 판정
	chainErr := audit.VerifyHashChain(r.auditPath)
	chainValid := (chainErr == nil)

	formatter := ui.NewTimelineFormatter(r.out)
	formatter.RenderTimeline(targetTraceID, chainValid, matchedEvents)

	return domain.ExitSuccess
}

func (r *AuditRunner) runVerify(ctx context.Context, args []string) domain.ExitCode {
	if err := audit.VerifyHashChain(r.auditPath); err != nil {
		fmt.Fprintf(r.out, "FAIL: audit hash chain is invalid or tampered: %v\n", err)
		return domain.ExitAuditFailure
	}
	fmt.Fprintln(r.out, "PASS: audit hash chain integrity verified successfully (SHA-256 chain intact)")
	return domain.ExitSuccess
}

func (r *AuditRunner) printUsage() {
	fmt.Fprintln(r.errOut, "Usage: authz-harness audit <command> [options]")
	fmt.Fprintln(r.errOut, "\nCommands:")
	fmt.Fprintln(r.errOut, "  timeline  단일 TraceID에 속한 다중 프로세스 감사 타임라인 및 계보 트리 시각화")
	fmt.Fprintln(r.errOut, "  verify    전체 audit.jsonl의 SHA-256 해시 체인 및 무결성 검증")
}
