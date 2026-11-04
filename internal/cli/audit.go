package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"authz-harness/internal/audit"
	"authz-harness/internal/audit/checkpoint"
	"authz-harness/internal/domain"
	"authz-harness/internal/ui"
)

// AuditRunner 는 `audit` 하위 명령어(timeline, verify)를 주관하는 러너다.
type AuditRunner struct {
	out       io.Writer
	errOut    io.Writer
	auditPath string
	privPath  string // Zone A 감사 체크포인트 서명 키
	pubPath   string // Zone B 감사 체크포인트 검증 키
	ckptPath  string // Zone B 기본 체크포인트 위치
}

// NewAuditRunner 는 AuditRunner 인스턴스를 생성한다.
// privKeyPath, pubJWKSPath 는 토큰 서명 키 위치이며, 감사 전용 키와 체크포인트의 기본 위치를 같은 구역에 둔다.
func NewAuditRunner(out, errOut io.Writer, auditPath, privKeyPath, pubJWKSPath string) *AuditRunner {
	return &AuditRunner{
		out:       out,
		errOut:    errOut,
		auditPath: auditPath,
		privPath:  filepath.Join(filepath.Dir(privKeyPath), "audit_signing_key.priv.json"),
		pubPath:   filepath.Join(filepath.Dir(pubJWKSPath), "audit_verification_key.pub.json"),
		ckptPath:  filepath.Join(filepath.Dir(pubJWKSPath), "audit_checkpoint.json"),
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
	case "tree":
		return r.runTree(args[1:])
	case "checkpoint":
		return r.runCheckpoint(args[1:])
	case "recover":
		return r.runRecover()
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
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	var ckpt string
	fs.StringVar(&ckpt, "checkpoint", "", "서명 체크포인트 파일 (지정 시 꼬리 절단·재작성·삭제도 검사)")
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	if ckpt != "" {
		if err := checkpoint.Verify(r.auditPath, ckpt, r.pubPath); err != nil {
			fmt.Fprintf(r.out, "FAIL: audit checkpoint verification failed: %v\n", err)
			return domain.ExitCodeFromError(err, domain.ExitAuditFailure)
		}
		fmt.Fprintln(r.out, "PASS: audit hash chain and signed checkpoint verified successfully")
		return domain.ExitSuccess
	}

	if err := audit.VerifyHashChain(r.auditPath); err != nil {
		fmt.Fprintf(r.out, "FAIL: audit hash chain is invalid or tampered: %v\n", err)
		return domain.ExitAuditFailure
	}
	fmt.Fprintln(r.out, "PASS: audit hash chain integrity verified successfully (SHA-256 chain intact)")
	return domain.ExitSuccess
}

// runTree 는 토큰(jti) 계보 기반 위임 트리를 출력한다. 보기 전용이며 해시로 검증되지 않은 metadata 필드를 포함한다.
func (r *AuditRunner) runTree(args []string) domain.ExitCode {
	fs := flag.NewFlagSet("audit tree", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	var traceID string
	fs.StringVar(&traceID, "trace-id", "", "대상 TraceID (생략 시 가장 최근 trace)")
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}

	f, err := os.Open(r.auditPath)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to open audit file '%s': %v\n", r.auditPath, err)
		return domain.ExitAuditFailure
	}
	defer f.Close()

	var all []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev audit.Event
		if json.Unmarshal([]byte(line), &ev) == nil {
			all = append(all, ev)
		}
	}
	if len(all) == 0 {
		fmt.Fprintf(r.errOut, "Error: no audit events found in %s\n", r.auditPath)
		return domain.ExitAuditFailure
	}

	target := strings.TrimSpace(traceID)
	if target == "" {
		for i := len(all) - 1; i >= 0; i-- {
			if all[i].TraceID != "" {
				target = all[i].TraceID
				break
			}
		}
	}
	if target == "" {
		fmt.Fprintf(r.errOut, "Error: --trace-id is required or no valid trace found\n")
		return domain.ExitBadInput
	}
	var matched []audit.Event
	for _, ev := range all {
		if ev.TraceID == target {
			matched = append(matched, ev)
		}
	}
	if len(matched) == 0 {
		fmt.Fprintf(r.errOut, "Error: no audit events found for trace ID '%s'\n", target)
		return domain.ExitBadInput
	}
	ui.NewTreeFormatter(r.out).Render(target, ui.BuildDelegationTree(matched))
	return domain.ExitSuccess
}

func (r *AuditRunner) runCheckpoint(args []string) domain.ExitCode {
	fs := flag.NewFlagSet("audit checkpoint", flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	out := r.ckptPath
	fs.StringVar(&out, "out", r.ckptPath, "체크포인트 출력 경로")
	if err := fs.Parse(args); err != nil {
		return domain.ExitBadInput
	}
	c, err := checkpoint.Create(r.auditPath, r.privPath, r.pubPath, out, domain.RealClock{})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to create audit checkpoint: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitAuditFailure)
	}
	fmt.Fprintf(r.out, "OK: checkpoint written to %s (records=%d, kid=%s)\n", out, c.LineCount, c.KeyID)
	return domain.ExitSuccess
}

// runRecover 는 기록 도중 충돌로 잘린 마지막 줄을 옆 파일로 보존하고 사슬을 복구한다(운영자 명령).
func (r *AuditRunner) runRecover() domain.ExitCode {
	res, err := audit.RecoverIncompleteTail(r.auditPath, domain.RealClock{})
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: audit recover refused: %v\n", err)
		return domain.ExitCodeFromError(err, domain.ExitAuditFailure)
	}
	if !res.Recovered {
		fmt.Fprintln(r.out, "OK: nothing to recover (audit tail is intact)")
		return domain.ExitSuccess
	}
	fmt.Fprintf(r.out, "OK: recovered incomplete tail (%d bytes, sha256=%s) saved to %s\n", res.TruncatedBytes, res.TruncatedSHA, res.PartialPath)
	return domain.ExitSuccess
}

func (r *AuditRunner) printUsage() {
	fmt.Fprintln(r.errOut, "Usage: authz-harness audit <command> [options]")
	fmt.Fprintln(r.errOut, "\nCommands:")
	fmt.Fprintln(r.errOut, "  timeline  단일 TraceID에 속한 다중 프로세스 감사 타임라인 및 계보 트리 시각화")
	fmt.Fprintln(r.errOut, "  verify    전체 audit.jsonl의 SHA-256 해시 체인 및 무결성 검증 (--checkpoint <path>: 서명 체크포인트 대조)")
	fmt.Fprintln(r.errOut, "  tree      토큰(jti) 계보 기반 위임 트리 (보기 전용, 해시로 검증되지 않은 metadata 필드 포함)")
	fmt.Fprintln(r.errOut, "  recover   기록 도중 충돌로 잘린 마지막 줄을 옆 파일로 보존하고 사슬 복구 (AUDIT_TAIL_INCOMPLETE 전용)")
	fmt.Fprintln(r.errOut, "  checkpoint 감사 체인 서명 체크포인트 생성 (--out <path>)")
}
