// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(audit.go)은 감사 추적(Audit Trail) 및 해시 체인 무결성을 검증하고 시각화하는 `audit` 서브커맨드 러너를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. 단방향 SHA-256 해시 체인 무결성 검증 (Append-Only Hash Chain):
//    - verify: 전체 audit.jsonl 의 해시 사슬을 역방향/정방향 검증하여 위변조, 줄 삭제, 순서 변경 여부를 탐지.
//    - --checkpoint 플래그 지정 시 Ed25519 서명된 체크포인트 파일과 대조하여 꼬리 절단(Tail Truncation)·재작성·삭제까지 검사.
// 2. 분산 추적 및 위임 계보 시각화 (Timeline & Delegation Tree):
//    - timeline: 단일 TraceID 에 속한 부모-자식 다중 프로세스 감사 이벤트를 시각적 ASCII 타임라인으로 렌더링.
//    - tree: JTI 기반 축소 위임 체인을 계층적 트리 구조로 렌더링.
// 3. 충돌 내구성 및 복구 (Crash Resilience & Recovery):
//    - checkpoint: 현재 체인의 마지막 레코드 번호와 해시를 감사 전용 Ed25519 서명 키(Zone A 폴더의 audit_signing_key.priv.json,
//      토큰 서명 키와 별개)로 서명하여 체크포인트 스냅샷 생성.
//    - recover: 전원 차단 등으로 마지막 줄이 불완전하게 잘린 경우(AUDIT_TAIL_INCOMPLETE),
//      잘린 데이터를 격리 파일로 보존하고 정상 줄까지만 복구하여 사슬 무결성을 회복.
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

// AuditRunner 는 `audit` 하위 명령어(timeline, verify, tree, checkpoint, recover)를 주관하는 러너다.
// 감사 로그 원장(audit.jsonl)과 체크포인트 서명 키를 관리하며 데이터 위변조를 판정한다.
type AuditRunner struct {
	out       io.Writer // 표준 출력 스트림
	errOut    io.Writer // 표준 에러 스트림
	auditPath string    // 감사 로그 파일 경로
	privPath  string    // Zone A 감사 체크포인트 서명 키
	pubPath   string    // Zone B 감사 체크포인트 검증 키
	ckptPath  string    // Zone B 기본 체크포인트 위치
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

// runTimeline 은 지정된 TraceID(또는 가장 최근 TraceID)의 감사 이벤트를 추출하여 타임라인 형태로 시각화한다.
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

	targetTraceID, matchedEvents, code := r.resolveTraceEvents(traceID, latest)
	if code != domain.ExitSuccess {
		return code
	}

	// 해시 체인 무결성 판정
	chainErr := audit.VerifyHashChain(r.auditPath)
	chainValid := (chainErr == nil)

	formatter := ui.NewTimelineFormatter(r.out)
	formatter.RenderTimeline(targetTraceID, chainValid, matchedEvents)

	return domain.ExitSuccess
}

// resolveTraceEvents 는 감사 로그에서 targetTraceID(생략 또는 latest 시 최신 trace)에 해당하는 이벤트를 필터링한다.
func (r *AuditRunner) resolveTraceEvents(traceID string, latest bool) (string, []audit.Event, domain.ExitCode) {
	allEvents, code := r.loadTraceEvents()
	if code != domain.ExitSuccess {
		return "", nil, code
	}

	target := strings.TrimSpace(traceID)
	if latest || target == "" {
		for i := len(allEvents) - 1; i >= 0; i-- {
			if allEvents[i].TraceID != "" {
				target = allEvents[i].TraceID
				break
			}
		}
	}

	if target == "" {
		fmt.Fprintf(r.errOut, "Error: --trace-id is required or no valid trace found\n")
		return "", nil, domain.ExitBadInput
	}

	var matched []audit.Event
	for _, ev := range allEvents {
		if ev.TraceID == target {
			matched = append(matched, ev)
		}
	}

	if len(matched) == 0 {
		fmt.Fprintf(r.errOut, "Error: no audit events found for trace ID '%s'\n", target)
		return "", nil, domain.ExitBadInput
	}

	return target, matched, domain.ExitSuccess
}

// loadTraceEvents 는 감사 파일을 읽어 파싱 가능한 줄만 모은다 (깨진 JSON 줄은 건너뛴다: 무결성 판정은 audit verify 의 몫).
// 줄 길이 상한은 audit.MaxRecordBytes 이며, 읽기 오류(상한 초과 포함)는 부분 출력 없이 ExitAuditFailure 로 끝낸다.
func (r *AuditRunner) loadTraceEvents() ([]audit.Event, domain.ExitCode) {
	f, err := os.Open(r.auditPath)
	if err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to open audit file '%s': %v\n", r.auditPath, err)
		return nil, domain.ExitAuditFailure
	}
	defer f.Close()

	var events []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), audit.MaxRecordBytes+1)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev audit.Event
		if json.Unmarshal([]byte(line), &ev) == nil {
			events = append(events, ev)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(r.errOut, "Error: failed to read audit file '%s': %v\n", r.auditPath, err)
		return nil, domain.ExitAuditFailure
	}
	if len(events) == 0 {
		fmt.Fprintf(r.errOut, "Error: no audit events found in %s\n", r.auditPath)
		return nil, domain.ExitAuditFailure
	}
	return events, domain.ExitSuccess
}

// runVerify 는 감사 로그의 SHA-256 해시 체인을 검증하고, 체크포인트 플래그 지정 시 Ed25519 서명 체크포인트와 대조한다.
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

	target, matched, code := r.resolveTraceEvents(traceID, false)
	if code != domain.ExitSuccess {
		return code
	}

	ui.NewTreeFormatter(r.out).Render(target, ui.BuildDelegationTree(matched))
	return domain.ExitSuccess
}

// runCheckpoint 는 감사 로그 체인의 상태를 읽어 서명 체크포인트 파일을 생성한다.
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
	if res.Kind == "newline_appended" {
		fmt.Fprintf(r.out, "OK: appended missing newline (1 byte) to complete record #%d; no data removed\n", res.RecordNumber)
		return domain.ExitSuccess
	}
	fmt.Fprintf(r.out, "OK: recovered incomplete tail (%d bytes, sha256=%s) saved to %s\n", res.TruncatedBytes, res.TruncatedSHA, res.PartialPath)
	return domain.ExitSuccess
}

// printUsage 는 audit 서브커맨드의 사용법 가이드를 출력한다.
func (r *AuditRunner) printUsage() {
	fmt.Fprintln(r.errOut, "Usage: authz-harness audit <command> [options]")
	fmt.Fprintln(r.errOut, "\nCommands:")
	fmt.Fprintln(r.errOut, "  timeline  단일 TraceID에 속한 다중 프로세스 감사 타임라인 및 계보 트리 시각화")
	fmt.Fprintln(r.errOut, "  verify    전체 audit.jsonl의 SHA-256 해시 체인 및 무결성 검증 (--checkpoint <path>: 서명 체크포인트 대조)")
	fmt.Fprintln(r.errOut, "  tree      토큰(jti) 계보 기반 위임 트리 (보기 전용, 해시로 검증되지 않은 metadata 필드 포함)")
	fmt.Fprintln(r.errOut, "  recover   기록 도중 충돌로 잘린 마지막 줄을 옆 파일로 보존하고 사슬 복구 (AUDIT_TAIL_INCOMPLETE 전용)")
	fmt.Fprintln(r.errOut, "  checkpoint 감사 체인 서명 체크포인트 생성 (--out <path>)")
}
