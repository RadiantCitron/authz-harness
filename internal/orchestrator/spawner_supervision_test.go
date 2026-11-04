package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/subagent"
)

func supervisedSpawner(t *testing.T, mode string, limits Limits, w audit.Writer) *SubprocessSpawner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := NewSubprocessSpawner(SpawnConfig{
		BinaryPath: exe,
		Args:       []string{"-test.run=TestHelperProcess", "--"},
		Limits:     limits,
		Audit:      w,
		ExtraEnv:   []string{"GO_WANT_HELPER_PROCESS=1", fmt.Sprintf("HELPER_MODE=%s", mode)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func supReq(trace string) subagent.SubagentRequest {
	return subagent.SubagentRequest{Version: "1.0", TraceID: trace, Token: "x", Action: "file:read", FilePath: "a.txt"}
}

func TestTC_020_06_HangTimesOut(t *testing.T) {
	res, err := supervisedSpawner(t, "hang", Limits{Timeout: 300 * time.Millisecond}, nil).Spawn(context.Background(), supReq("tr-020-06"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Termination != TermTimedOut || res.ExitCode != 17 || res.Reason != domain.ReasonResourceTimeout || !res.TimedOut {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestTC_020_07_GrandchildKilled(t *testing.T) {
	res, err := supervisedSpawner(t, "spawn_child_hang", Limits{Timeout: 500 * time.Millisecond}, nil).Spawn(context.Background(), supReq("tr-020-07"))
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 17 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
	m := regexp.MustCompile(`CHILD_PID=(\d+)`).FindStringSubmatch(res.StdoutRaw)
	if m == nil {
		t.Fatalf("no CHILD_PID in %q", res.StdoutRaw)
	}
	pid, _ := strconv.Atoi(m[1])
	if !harness.WaitForProcessGone(pid, time.Second) {
		t.Fatalf("grandchild %d still alive", pid)
	}
}

func TestTC_020_08_FloodExceedsOutput(t *testing.T) {
	res, err := supervisedSpawner(t, "flood", Limits{Timeout: 5 * time.Second, MaxOutputBytes: 16 * 1024}, nil).Spawn(context.Background(), supReq("tr-020-08"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Termination != TermOutputExceeded || res.ExitCode != 17 || res.Reason != domain.ReasonResourceOutputLimit {
		t.Fatalf("unexpected: %+v", res.Termination)
	}
	if len(res.StdoutRaw) > 16384 || res.Duration >= 5*time.Second {
		t.Fatalf("len=%d dur=%v", len(res.StdoutRaw), res.Duration)
	}
}

func TestTC_020_09_SelfKillSignaled(t *testing.T) {
	res, err := supervisedSpawner(t, "self_kill", Limits{Timeout: 5 * time.Second}, nil).Spawn(context.Background(), supReq("tr-020-09"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Termination != TermSignaled || res.ExitCode != 16 || res.Reason != domain.ReasonSubprocessAbnormalExit || res.Signal != "killed" {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestTC_020_10_NonStandardExit(t *testing.T) {
	res, err := supervisedSpawner(t, "exit_2", Limits{Timeout: 5 * time.Second}, nil).Spawn(context.Background(), supReq("tr-020-10"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Termination != TermExited || res.RawExitCode != 2 || res.ExitCode != 16 {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestTC_020_11_ParentCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	res, err := supervisedSpawner(t, "hang", Limits{Timeout: 10 * time.Second}, nil).Spawn(ctx, supReq("tr-020-11"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Termination != TermCanceled || res.ExitCode != 16 {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestTC_020_12_LimitAudit(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := supervisedSpawner(t, "hang", Limits{Timeout: 300 * time.Millisecond}, w).Spawn(context.Background(), supReq("tr-020-12")); err != nil {
		t.Fatal(err)
	}
	events, err := readAuditEvents(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last.Action != AuditActionLimitExceeded || last.Decision != "deny" || last.Reason != string(domain.ReasonResourceTimeout) {
		t.Fatalf("unexpected last event: %+v", last)
	}
	if verr := audit.VerifyHashChain(auditPath); verr != nil {
		t.Fatalf("chain invalid: %v", verr)
	}
}

type failOnSecondWriter struct{ n atomic.Int32 }

func (f *failOnSecondWriter) Log(audit.Event) error {
	if f.n.Add(1) >= 2 {
		return errors.New("disk full")
	}
	return nil
}
func (f *failOnSecondWriter) Close() error { return nil }

func TestTC_020_13_LimitAuditFailureFailsClosed(t *testing.T) {
	_, err := supervisedSpawner(t, "hang", Limits{Timeout: 300 * time.Millisecond}, &failOnSecondWriter{}).Spawn(context.Background(), supReq("tr-020-13"))
	var de *domain.Error
	if !errors.As(err, &de) || de.ExitCode != domain.ExitAuditFailure {
		t.Fatalf("want audit failure, got %v", err)
	}
}
