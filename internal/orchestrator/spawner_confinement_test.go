package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
	"authz-harness/internal/subagent"
)

type recWriter struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *recWriter) Log(e audit.Event) error {
	r.mu.Lock()
	r.evs = append(r.evs, e)
	r.mu.Unlock()
	return nil
}
func (r *recWriter) Close() error { return nil }
func (r *recWriter) steps() []string {
	var s []string
	for _, e := range r.evs {
		s = append(s, e.Step)
	}
	return s
}

// wrapEnvConfiner 는 cmd 를 /usr/bin/env 로 감싸는 테스트 전용 가짜 Confiner 다.
type wrapEnvConfiner struct{}

func (wrapEnvConfiner) Name() string    { return "fake-env" }
func (wrapEnvConfiner) Available() bool { return true }
func (wrapEnvConfiner) Prepare(cmd *exec.Cmd, _ confinement.Policy) error {
	args := append([]string{"env", cmd.Path}, cmd.Args[1:]...)
	cmd.Path, cmd.Args = "/usr/bin/env", args
	return nil
}

func confSpawner(t *testing.T, mode string, w audit.Writer, extra []string, c confinement.Confiner, pol confinement.Policy) *SubprocessSpawner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSubprocessSpawner(SpawnConfig{
		BinaryPath:  exe,
		Args:        []string{"-test.run=TestHelperProcess", "--"},
		Limits:      Limits{Timeout: 10 * time.Second},
		Audit:       w,
		ExtraEnv:    append([]string{"GO_WANT_HELPER_PROCESS=1", "HELPER_MODE=" + mode}, extra...),
		Confiner:    c,
		Confinement: pol,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func confReq(id string) subagent.SubagentRequest {
	return subagent.SubagentRequest{Version: "1.0", TraceID: id, Token: "x", Action: "file:read", FilePath: "a.txt"}
}

func countStep(w *recWriter, step string) int {
	n := 0
	for _, e := range w.evs {
		if e.Step == step {
			n++
		}
	}
	return n
}

func TestSpawnerConfinement(t *testing.T) {
	deny := func(t *testing.T, c confinement.Confiner) {
		marker := filepath.Join(t.TempDir(), "started")
		w := &recWriter{}
		s := confSpawner(t, "write_marker", w, []string{"MARKER_FILE=" + marker}, c, confinement.Policy{Require: true, ProtectedRoot: "/r"})
		res, err := s.Spawn(context.Background(), confReq("tr-deny"))
		if err != nil {
			t.Fatal(err)
		}
		if _, e := os.Stat(marker); e == nil {
			t.Fatal("child must not start")
		}
		if res.ExitCode != 16 || res.Reason != domain.ReasonConfinementUnavailable {
			t.Fatalf("got %d %s", res.ExitCode, res.Reason)
		}
		var conf *audit.Event
		for i := range w.evs {
			if w.evs[i].Action == AuditActionAgentConfined {
				conf = &w.evs[i]
			}
		}
		if conf == nil || conf.Decision != "deny" || countStep(w, "ORCHESTRATE_COLLECT") != 0 {
			t.Fatalf("audit wrong: %v", w.steps())
		}
	}
	t.Run("TC-040-01 필수 + Confiner nil", func(t *testing.T) { deny(t, nil) })
	t.Run("TC-040-02 필수 + Noop", func(t *testing.T) { deny(t, confinement.NoopConfiner{}) })

	t.Run("TC-040-03 비필수 + Noop 대조군", func(t *testing.T) {
		w := &recWriter{}
		s := confSpawner(t, "normal", w, nil, confinement.NoopConfiner{}, confinement.Policy{ProtectedRoot: "/r"})
		res, err := s.Spawn(context.Background(), confReq("tr-ctl"))
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("%v %+v", err, res)
		}
		found := false
		for _, e := range w.evs {
			if e.Action == AuditActionAgentConfined && e.Decision == "allow" && e.Metadata["confiner"] == "none" {
				found = true
			}
		}
		if !found {
			t.Fatalf("allow/none audit missing: %v", w.steps())
		}
	})

	t.Run("TC-040-04 영값은 기존 2이벤트", func(t *testing.T) {
		w := &recWriter{}
		s := confSpawner(t, "normal", w, nil, nil, confinement.Policy{})
		if _, err := s.Spawn(context.Background(), confReq("tr-zero")); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(w.steps()); got != "[ORCHESTRATE_SPAWN ORCHESTRATE_COLLECT]" {
			t.Fatalf("steps=%s", got)
		}
	})

	t.Run("TC-040-05 래핑 투명성", func(t *testing.T) {
		if _, err := os.Stat("/usr/bin/env"); err != nil {
			t.Skip("no /usr/bin/env")
		}
		plain, err := confSpawner(t, "normal", nil, nil, nil, confinement.Policy{}).Spawn(context.Background(), confReq("tr-w"))
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := confSpawner(t, "normal", nil, nil, wrapEnvConfiner{}, confinement.Policy{ProtectedRoot: "/r"}).Spawn(context.Background(), confReq("tr-w"))
		if err != nil {
			t.Fatal(err)
		}
		if wrapped.ExitCode != plain.ExitCode || wrapped.Termination != plain.Termination || wrapped.Response == nil ||
			wrapped.Response.Output != plain.Response.Output {
			t.Fatalf("wrapping not transparent: %+v vs %+v", wrapped, plain)
		}
	})

	t.Run("TC-040-06 exit 13 재해석 없음", func(t *testing.T) {
		w := &recWriter{}
		s := confSpawner(t, "exit_13", w, nil, wrapEnvConfiner{}, confinement.Policy{ProtectedRoot: "/r"})
		res, err := s.Spawn(context.Background(), confReq("tr-13"))
		if err != nil || res.ExitCode != 13 {
			t.Fatalf("%v %+v", err, res)
		}
		if countStep(w, "ORCHESTRATE_CONFINE") != 1 || countStep(w, "ORCHESTRATE_COLLECT") != 1 {
			t.Fatalf("steps=%v", w.steps())
		}
		for _, e := range w.evs {
			if e.Step == "ORCHESTRATE_CONFINE" && e.Decision != "allow" {
				t.Fatal("confine must be allow only")
			}
		}
	})
}
