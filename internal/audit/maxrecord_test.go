package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

func padEvent(n int) audit.Event {
	return audit.Event{TraceID: "t", Actor: "a", Action: "x", Resource: strings.Repeat("r", n), Decision: "allow", Success: true}
}

func wantReason(t *testing.T, err error, reason domain.Reason) {
	t.Helper()
	de, ok := err.(*domain.Error)
	if !ok || de.Reason != reason {
		t.Fatalf("want reason %s, got %v", reason, err)
	}
}

func lastLineLen(t *testing.T, path string) int {
	t.Helper()
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return len(lines[len(lines)-1])
}

// AT-S2-01
func TestMaxRecord_OverLimitRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	w, _ := audit.NewJSONLWriter(p)
	defer w.Close()
	if err := w.Log(padEvent(0)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	err := w.Log(padEvent(audit.MaxRecordBytes))
	wantReason(t, err, domain.ReasonAuditLogFailed)
	after, _ := os.Stat(p)
	if before.Size() != after.Size() {
		t.Fatal("file changed")
	}
	if err := audit.VerifyHashChain(p); err != nil {
		t.Fatal(err)
	}
}

// AT-S2-02, AT-S2-04
func TestMaxRecord_ExactLimitAndLongLastLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	w, _ := audit.NewJSONLWriter(p)
	defer w.Close()
	if err := w.Log(padEvent(0)); err != nil {
		t.Fatal(err)
	}
	// 정확히 상한이 되도록 보정한다(타임스탬프 길이 변동 대응).
	pad := audit.MaxRecordBytes - lastLineLen(t, p)
	for i := 0; i < 40; i++ {
		tmp := filepath.Join(dir, "probe.jsonl")
		cur, _ := os.ReadFile(p)
		_ = os.WriteFile(tmp, cur, 0o600)
		pw, _ := audit.NewJSONLWriter(tmp)
		err := pw.Log(padEvent(pad))
		pw.Close()
		if err != nil {
			pad -= 64
			continue
		}
		d := audit.MaxRecordBytes - lastLineLen(t, tmp)
		if d == 0 {
			break
		}
		pad += d
	}
	if err := w.Log(padEvent(pad)); err != nil {
		t.Fatalf("exact-limit log: %v", err)
	}
	if got := lastLineLen(t, p); got > audit.MaxRecordBytes || got < audit.MaxRecordBytes-16 {
		t.Fatalf("line len %d not near limit", got)
	}
	if err := audit.VerifyHashChain(p); err != nil {
		t.Fatal(err)
	}
	// AT-S2-04: 64KB 초과 마지막 줄 뒤에도 이어 쓰기
	if err := w.Log(padEvent(0)); err != nil {
		t.Fatalf("log after long last line: %v", err)
	}
	if err := audit.VerifyHashChain(p); err != nil {
		t.Fatal(err)
	}
}

// AT-S2-03
func TestMaxRecord_InjectedOversizeLineBroken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	w, _ := audit.NewJSONLWriter(p)
	_ = w.Log(padEvent(0))
	w.Close()
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(strings.Repeat("x", audit.MaxRecordBytes+10) + "\n")
	f.Close()
	wantReason(t, audit.VerifyHashChain(p), domain.ReasonAuditIntegrityBroken)
}
