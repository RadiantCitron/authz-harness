package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/cli"
	"authz-harness/internal/domain"
)

// 계획 021 S1 — DUP-05: audit timeline/tree 조회의 줄 길이 상한과 오류 처리 (인수 시험 T1~T5).

func rawLine(t *testing.T, trace, step string, padLen int) string {
	t.Helper()
	b, err := json.Marshal(audit.Event{Timestamp: time.Unix(1, 0).UTC(), TraceID: trace, Step: step, Actor: "a", Action: "x", Resource: strings.Repeat("r", padLen), Success: true})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// exactLine 은 JSON 길이가 정확히 size 바이트인 한 줄을 만든다.
func exactLine(t *testing.T, trace, step string, size int) string {
	t.Helper()
	base := len(rawLine(t, trace, step, 1)) // resource 키가 omitempty 라 1자 기준으로 센다
	line := rawLine(t, trace, step, size-base+1)
	if len(line) != size {
		t.Fatalf("line len %d want %d", len(line), size)
	}
	return line
}

func runAuditCmd(t *testing.T, lines []string, args ...string) (domain.ExitCode, string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	r := cli.NewAuditRunner(&out, &errOut, p, filepath.Join(dir, "priv", "k.json"), filepath.Join(dir, "pub", "j.json"))
	code := r.Run(context.Background(), args)
	return code, out.String(), errOut.String()
}

// T1: 100KB 기록이 있어도 timeline 이 정상 출력한다.
func TestAuditLoad_T1_Timeline100KB(t *testing.T) {
	code, out, errOut := runAuditCmd(t, []string{rawLine(t, "t-big", "big.step", 100*1024)}, "timeline", "--trace-id", "t-big")
	if code != domain.ExitSuccess || !strings.Contains(out, "big.step") {
		t.Fatalf("code=%v out=%q err=%q", code, out, errOut)
	}
}

// T2: 정확히 MaxRecordBytes 인 기록도 timeline·tree 가 읽는다.
func TestAuditLoad_T2_ExactMaxRecord(t *testing.T) {
	for _, sub := range [][]string{{"timeline", "--trace-id", "t-max"}, {"tree", "--trace-id", "t-max"}} {
		code, out, errOut := runAuditCmd(t, []string{exactLine(t, "t-max", "max.step", audit.MaxRecordBytes)}, sub...)
		if code != domain.ExitSuccess {
			t.Fatalf("%s: code=%v out=%q err=%q", sub[0], code, out, errOut)
		}
	}
}

// T3: 상한을 넘는 줄이 끼어 있으면 부분 출력 없이 ExitAuditFailure.
func TestAuditLoad_T3_OverLimitFailsWithoutPartialOutput(t *testing.T) {
	lines := []string{
		rawLine(t, "t-ok", "before.step", 10),
		rawLine(t, "t-ok", "huge.step", audit.MaxRecordBytes+100),
		rawLine(t, "t-ok", "after.step", 10),
	}
	for _, sub := range [][]string{{"timeline", "--trace-id", "t-ok"}, {"tree", "--trace-id", "t-ok"}} {
		code, out, _ := runAuditCmd(t, lines, sub...)
		if code != domain.ExitAuditFailure {
			t.Fatalf("%s: want ExitAuditFailure, got %v", sub[0], code)
		}
		if strings.Contains(out, "before.step") {
			t.Fatalf("%s: partial output forbidden: %q", sub[0], out)
		}
	}
}

// T4: --trace-id 생략과 --latest 는 가장 최근 TraceID 를 고른다.
func TestAuditLoad_T4_LatestTrace(t *testing.T) {
	lines := []string{rawLine(t, "t-old", "old.step", 1), rawLine(t, "t-new", "new.step", 1)}
	for _, args := range [][]string{{"timeline"}, {"timeline", "--latest"}} {
		code, out, errOut := runAuditCmd(t, lines, args...)
		if code != domain.ExitSuccess || !strings.Contains(out, "new.step") || strings.Contains(out, "old.step") {
			t.Fatalf("%v: code=%v out=%q err=%q", args, code, out, errOut)
		}
	}
}

// T5: 깨진 JSON 줄은 건너뛰고 나머지를 출력한다 (D-03).
func TestAuditLoad_T5_BrokenJSONLineSkipped(t *testing.T) {
	lines := []string{rawLine(t, "t-mix", "good1.step", 1), "{not json", rawLine(t, "t-mix", "good2.step", 1)}
	code, out, errOut := runAuditCmd(t, lines, "timeline", "--trace-id", "t-mix")
	if code != domain.ExitSuccess || !strings.Contains(out, "good1.step") || !strings.Contains(out, "good2.step") {
		t.Fatalf("code=%v out=%q err=%q", code, out, errOut)
	}
}
