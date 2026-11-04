package checkpoint_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/audit/checkpoint"
	"authz-harness/internal/domain"
)

type env struct {
	dir, auditPath, priv, pub, ckpt string
}

func setup(t *testing.T, n int) *env {
	t.Helper()
	d := t.TempDir()
	e := &env{dir: d, auditPath: filepath.Join(d, "audit.jsonl"),
		priv: filepath.Join(d, "a", "priv.json"), pub: filepath.Join(d, "b", "pub.json"), ckpt: filepath.Join(d, "b", "ckpt.json")}
	w, err := audit.NewJSONLWriter(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := w.Log(audit.Event{Timestamp: time.Date(2026, 11, 4, 10, 0, i, 0, time.UTC), TraceID: "t", Actor: "a", Action: "x", Resource: "r", Decision: "allow", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	return e
}

func (e *env) create(t *testing.T) {
	t.Helper()
	if _, err := checkpoint.Create(e.auditPath, e.priv, e.pub, e.ckpt, domain.RealClock{}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) verify() error { return checkpoint.Verify(e.auditPath, e.ckpt, e.pub) }

func want(t *testing.T, err error, r domain.Reason) {
	t.Helper()
	if domain.ReasonFromError(err, "") != r || domain.ExitCodeFromError(err, 0) != domain.ExitAuditFailure {
		t.Fatalf("want %s/15, got %v", r, err)
	}
}

func lines(t *testing.T, p string) []string {
	b, _ := os.ReadFile(p)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestTailTruncation(t *testing.T) { // TC-040-01
	e := setup(t, 5)
	e.create(t)
	if err := e.verify(); err != nil {
		t.Fatal(err)
	}
	l := lines(t, e.auditPath)
	_ = os.WriteFile(e.auditPath, []byte(strings.Join(l[:4], "\n")+"\n"), 0o600)
	want(t, e.verify(), domain.ReasonAuditTruncationDetected)
}

func TestFullRewrite(t *testing.T) { // TC-040-02
	e := setup(t, 5)
	e.create(t)
	l := lines(t, e.auditPath)
	prev := ""
	if len(l) != 5 {
		t.Fatal("fixture")
	}
	for i := range l {
		var ev audit.Event
		_ = json.Unmarshal([]byte(l[i]), &ev)
		if i == 1 {
			ev.Resource = "tampered"
		}
		if i >= 1 {
			ev.PrevHash = prev
			ev.CurrHash = audit.ComputeEventHash(prev, ev)
			ev.Metadata = nil
		}
		prev = ev.CurrHash
		b, _ := json.Marshal(ev)
		l[i] = string(b)
	}
	_ = os.WriteFile(e.auditPath, []byte(strings.Join(l, "\n")+"\n"), 0o600)
	if err := audit.VerifyHashChain(e.auditPath); err != nil {
		t.Fatalf("rewritten chain should itself be valid: %v", err)
	}
	want(t, e.verify(), domain.ReasonAuditCheckpointMismatch)
}

func TestDeleteOrEmpty(t *testing.T) { // TC-040-03
	e := setup(t, 3)
	e.create(t)
	_ = os.Remove(e.auditPath)
	want(t, e.verify(), domain.ReasonAuditTruncationDetected)
	_ = os.WriteFile(e.auditPath, nil, 0o600)
	want(t, e.verify(), domain.ReasonAuditTruncationDetected)
}

func TestForgedOrMissingCheckpointInputs(t *testing.T) { // TC-040-04
	e := setup(t, 3)
	e.create(t)
	good, _ := os.ReadFile(e.ckpt)

	_ = os.Remove(e.ckpt)
	want(t, e.verify(), domain.ReasonAuditCheckpointMismatch)

	_ = os.WriteFile(e.ckpt, good, 0o644)
	pubGood, _ := os.ReadFile(e.pub)
	_ = os.Remove(e.pub)
	want(t, e.verify(), domain.ReasonAuditCheckpointMismatch)
	_ = os.WriteFile(e.pub, pubGood, 0o644)

	var c checkpoint.Checkpoint
	_ = json.Unmarshal(good, &c)
	c.LineCount++
	b, _ := json.Marshal(c)
	_ = os.WriteFile(e.ckpt, b, 0o644)
	want(t, e.verify(), domain.ReasonAuditCheckpointMismatch)

	// 다른 키 쌍으로 서명한 체크포인트
	o := setup(t, 3)
	o.create(t)
	other, _ := os.ReadFile(o.ckpt)
	_ = os.WriteFile(e.ckpt, other, 0o644)
	want(t, e.verify(), domain.ReasonAuditCheckpointMismatch)
}

func TestAppendAfterCheckpointOK(t *testing.T) { // TC-040-05
	e := setup(t, 3)
	e.create(t)
	w, _ := audit.NewJSONLWriter(e.auditPath)
	if err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Success: true}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := e.verify(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDoesNotCreateKeys(t *testing.T) { // TC-040-06
	e := setup(t, 2)
	want(t, e.verify(), domain.ReasonAuditCheckpointMismatch)
	for _, p := range []string{e.priv, e.pub} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("key file created by Verify: %s", p)
		}
	}
}

func TestCreateRefusesEmptyAndHalfKeyPair(t *testing.T) {
	e := setup(t, 0)
	if _, err := checkpoint.Create(e.auditPath, e.priv, e.pub, e.ckpt, domain.RealClock{}); err == nil {
		t.Fatal("empty audit must not be signed")
	}
	e = setup(t, 2)
	_ = os.MkdirAll(filepath.Dir(e.priv), 0o755)
	_ = os.WriteFile(e.priv, []byte("{}"), 0o600)
	if _, err := checkpoint.Create(e.auditPath, e.priv, e.pub, e.ckpt, domain.RealClock{}); err == nil {
		t.Fatal("half key pair must fail closed")
	}
}
