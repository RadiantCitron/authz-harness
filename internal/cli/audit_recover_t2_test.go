package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// seedT2 는 정상 기록 2줄 중 2번째 줄의 마지막 \n 1바이트를 제거한 파일(V-01)을 만든다.
func seedT2(t *testing.T) (dir, path string, orig []byte) {
	t.Helper()
	dir, path = seedTorn(t, "")
	b, _ := os.ReadFile(path)
	ls := strings.SplitAfter(string(b), "\n")                                           // 3줄 + ""
	orig = []byte(ls[0])                                                                // 앞 1줄 (줄바꿈 포함)
	t2 := append(append([]byte{}, orig...), []byte(strings.TrimSuffix(ls[1], "\n"))...) // 2번째 줄의 \n 제거
	if err := os.WriteFile(path, t2, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path, orig
}

func lastEvent(t *testing.T, path string) audit.Event {
	t.Helper()
	b, _ := os.ReadFile(path)
	ls := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	var ev audit.Event
	if err := json.Unmarshal([]byte(ls[len(ls)-1]), &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// AT-S2-01, AT-S2-02, AT-S2-06
func TestAuditRecover_T2AppendsNewlineOnly(t *testing.T) {
	dir, path, orig := seedT2(t)
	tailRec, _ := os.ReadFile(path)
	tailRec = tailRec[len(orig):]
	r, out, errOut := runner(dir, path)
	ctx := context.Background()
	if c := r.Run(ctx, []string{"recover"}); c != domain.ExitSuccess {
		t.Fatalf("recover: %v %s", c, errOut)
	}
	if len(partials(t, path)) != 0 {
		t.Fatal("T2 must not create a partial file")
	}
	after, _ := os.ReadFile(path)
	want := append(append([]byte{}, orig...), tailRec...)
	if !bytes.HasPrefix(after, append(want, '\n')) {
		t.Fatal("original records must be byte-identical, followed by exactly one appended newline")
	}
	if n := lineCount(t, path); n != 3 {
		t.Fatalf("lines %d, want 3 (2 original + recover event)", n)
	}
	ev := lastEvent(t, path)
	if ev.Action != "audit.recovered" || ev.Resource != "newline-appended:#2" || ev.Metadata["recovery_kind"] != "newline_appended" {
		t.Fatalf("recover event: %+v", ev)
	}
	if !strings.Contains(out.String(), "#2") {
		t.Fatalf("stdout lacks record number: %s", out)
	}
	// AT-S2-02
	if c := r.Run(ctx, []string{"verify"}); c != domain.ExitSuccess {
		t.Fatalf("verify: %v", c)
	}
	w, _ := audit.NewJSONLWriter(path)
	if err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Success: true}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	w.Close()
	if c := r.Run(ctx, []string{"verify"}); c != domain.ExitSuccess {
		t.Fatalf("verify after Log: %v", c)
	}
	// AT-S2-06
	before, _ := os.ReadFile(path)
	out.Reset()
	if c := r.Run(ctx, []string{"recover"}); c != domain.ExitSuccess || !strings.Contains(out.String(), "nothing to recover") {
		t.Fatalf("second recover: %v %s", c, out)
	}
	if a, _ := os.ReadFile(path); !bytes.Equal(before, a) {
		t.Fatal("second recover changed file")
	}
}

// AT-S2-03
func TestAuditRecover_T2WithCheckpoint(t *testing.T) {
	dir, path := seedTorn(t, "")
	b, _ := os.ReadFile(path)
	ls := strings.SplitAfter(string(b), "\n")
	_ = os.WriteFile(path, []byte(ls[0]), 0o600) // 1줄 상태
	r, out, errOut := runner(dir, path)
	ctx := context.Background()
	if c := r.Run(ctx, []string{"checkpoint"}); c != domain.ExitSuccess {
		t.Fatalf("checkpoint: %v %s", c, errOut)
	}
	_ = os.WriteFile(path, []byte(ls[0]+strings.TrimSuffix(ls[1], "\n")), 0o600)
	if c := r.Run(ctx, []string{"recover"}); c != domain.ExitSuccess {
		t.Fatalf("recover: %v %s", c, errOut)
	}
	ck := dir + "/pub/audit_checkpoint.json"
	if c := r.Run(ctx, []string{"verify", "--checkpoint", ck}); c != domain.ExitSuccess {
		t.Fatalf("verify --checkpoint: %v %s", c, out)
	}
}

// AT-S2-04: 줄바꿈 없는 변조 꼬리는 복구를 거부한다.
func TestAuditRecover_T3Refused(t *testing.T) {
	dir, path, _ := seedT2(t)
	b, _ := os.ReadFile(path)
	b = bytes.Replace(b, []byte(`"action":"x"`), []byte(`"action":"y"`), -1)
	_ = os.WriteFile(path, b, 0o600)
	before, _ := os.ReadFile(path)
	r, _, _ := runner(dir, path)
	if c := r.Run(context.Background(), []string{"recover"}); c != domain.ExitAuditFailure {
		t.Fatalf("got %v", c)
	}
	if _, err := audit.RecoverIncompleteTail(path, domain.RealClock{}); err == nil {
		t.Fatal("want error")
	} else if de, ok := err.(*domain.Error); !ok || de.Reason != domain.ReasonAuditIntegrityBroken {
		t.Fatalf("got %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) || len(partials(t, path)) != 0 {
		t.Fatal("state changed")
	}
}

// AT-S2-05: T1 복구 이벤트에 recovery_kind=tail_moved 가 남는다.
func TestAuditRecover_T1KindMarked(t *testing.T) {
	dir, path := seedTorn(t, tornTail)
	r, _, errOut := runner(dir, path)
	if c := r.Run(context.Background(), []string{"recover"}); c != domain.ExitSuccess {
		t.Fatalf("recover: %v %s", c, errOut)
	}
	if ev := lastEvent(t, path); ev.Metadata["recovery_kind"] != "tail_moved" {
		t.Fatalf("event: %+v", ev)
	}
}
