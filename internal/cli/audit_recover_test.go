package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/cli"
	"authz-harness/internal/domain"
)

const tornTail = `{"trace_id":"t","actor":"a","act`

// seedTorn 은 정상 3줄 + 줄바꿈 없는 잘린 조각 파일을 만든다.
func seedTorn(t *testing.T, tail string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "audit.jsonl")
	w, err := audit.NewJSONLWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(tail)
	f.Close()
	return dir, path
}

func runner(dir, path string) (*cli.AuditRunner, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return cli.NewAuditRunner(&out, &errOut, path, filepath.Join(dir, "priv", "s.json"), filepath.Join(dir, "pub", "j.json")), &out, &errOut
}

func lineCount(t *testing.T, p string) int {
	b, _ := os.ReadFile(p)
	return strings.Count(string(b), "\n")
}

func partials(t *testing.T, path string) []string {
	m, _ := filepath.Glob(path + ".partial-*")
	return m
}

// AT-S3-01, AT-S3-02, AT-S3-03
func TestAuditRecover_TornTail(t *testing.T) {
	dir, path := seedTorn(t, "")
	r, out, errOut := runner(dir, path)
	ctx := context.Background()
	if c := r.Run(ctx, []string{"checkpoint"}); c != domain.ExitSuccess { // 3줄 상태 체크포인트
		t.Fatalf("checkpoint: %v %s", c, errOut)
	}
	ck := filepath.Join(dir, "pub", "audit_checkpoint.json")
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(tornTail)
	f.Close()
	before, _ := os.ReadFile(path)

	// AT-S3-01
	w, _ := audit.NewJSONLWriter(path)
	err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Success: true})
	w.Close()
	if de, ok := err.(*domain.Error); !ok || de.Reason != domain.ReasonAuditTailIncomplete {
		t.Fatalf("Log: want TAIL_INCOMPLETE, got %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("Log changed the file")
	}
	out.Reset()
	if c := r.Run(ctx, []string{"verify"}); c != domain.ExitAuditFailure || !strings.Contains(out.String(), "AUDIT_TAIL_INCOMPLETE") {
		t.Fatalf("verify: %v %s", c, out)
	}

	// AT-S3-02
	if c := r.Run(ctx, []string{"recover"}); c != domain.ExitSuccess {
		t.Fatalf("recover: %v %s", c, errOut)
	}
	ps := partials(t, path)
	if len(ps) != 1 {
		t.Fatalf("partials: %v", ps)
	}
	if b, _ := os.ReadFile(ps[0]); string(b) != tornTail {
		t.Fatalf("partial content %q", b)
	}
	if st, _ := os.Stat(ps[0]); st.Mode().Perm() != 0o600 {
		t.Fatalf("partial perm %v", st.Mode().Perm())
	}
	if n := lineCount(t, path); n != 4 {
		t.Fatalf("lines %d", n)
	}
	if c := r.Run(ctx, []string{"verify"}); c != domain.ExitSuccess {
		t.Fatalf("verify after recover: %v", c)
	}
	// AT-S3-03
	if c := r.Run(ctx, []string{"verify", "--checkpoint", ck}); c != domain.ExitSuccess {
		t.Fatalf("verify --checkpoint after recover: %v %s", c, out)
	}
	w, _ = audit.NewJSONLWriter(path)
	defer w.Close()
	if err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Success: true}); err != nil {
		t.Fatalf("Log after recover: %v", err)
	}
}

// AT-S3-04
func TestAuditRecover_NewlineTerminatedGarbageRefused(t *testing.T) {
	dir, path := seedTorn(t, "{garbage\n")
	before, _ := os.ReadFile(path)
	r, _, _ := runner(dir, path)
	if c := r.Run(context.Background(), []string{"recover"}); c != domain.ExitAuditFailure {
		t.Fatalf("got %v", c)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) || len(partials(t, path)) != 0 {
		t.Fatal("state changed")
	}
}

// AT-S3-05
func TestAuditRecover_BrokenChainRefused(t *testing.T) {
	dir, path := seedTorn(t, tornTail)
	b, _ := os.ReadFile(path)
	ls := strings.Split(string(b), "\n")
	ls[1] = strings.Replace(ls[1], `"curr_hash":"`, `"curr_hash":"0`, 1)
	b = []byte(strings.Join(ls, "\n"))
	_ = os.WriteFile(path, b, 0o600)
	_, err := audit.RecoverIncompleteTail(path, domain.RealClock{})
	if de, ok := err.(*domain.Error); !ok || de.Reason != domain.ReasonAuditIntegrityBroken {
		t.Fatalf("got %v", err)
	}
	r, _, _ := runner(dir, path)
	if c := r.Run(context.Background(), []string{"recover"}); c != domain.ExitAuditFailure {
		t.Fatalf("got %v", c)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(b, after) || len(partials(t, path)) != 0 {
		t.Fatal("state changed")
	}
}

// AT-S3-06, AT-S3-07
func TestAuditRecover_NothingToDo(t *testing.T) {
	dir, path := seedTorn(t, "")
	before, _ := os.ReadFile(path)
	r, out, _ := runner(dir, path)
	if c := r.Run(context.Background(), []string{"recover"}); c != domain.ExitSuccess || !strings.Contains(out.String(), "nothing to recover") {
		t.Fatalf("intact: %v %s", c, out)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("intact file changed")
	}
	empty := filepath.Join(dir, "empty.jsonl")
	_ = os.WriteFile(empty, nil, 0o600)
	for _, p := range []string{empty, filepath.Join(dir, "missing.jsonl")} {
		r2, out2, _ := runner(dir, p)
		if c := r2.Run(context.Background(), []string{"recover"}); c != domain.ExitSuccess || !strings.Contains(out2.String(), "nothing to recover") {
			t.Fatalf("%s: %v %s", p, c, out2)
		}
	}
}
