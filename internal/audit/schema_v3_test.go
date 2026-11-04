package audit_test

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

func v3Ev(i, ver int) audit.Event {
	return audit.Event{
		SchemaVersion: ver, Timestamp: time.Date(2026, 11, 5, 10, 0, i, 0, time.UTC),
		TraceID: "t", Actor: "a", Action: "x", Resource: "r", Decision: "allow", Success: true,
	}
}

func chainLines(t *testing.T, evs ...audit.Event) string {
	t.Helper()
	prev := ""
	var sb strings.Builder
	for _, e := range evs {
		e.PrevHash = prev
		e.CurrHash = audit.ComputeEventHash(prev, e)
		prev = e.CurrHash
		b, _ := json.Marshal(e)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func broken(t *testing.T, err error) {
	t.Helper()
	if domain.ReasonFromError(err, "") != domain.ReasonAuditIntegrityBroken {
		t.Fatalf("want integrity broken, got %v", err)
	}
}

// AT-S4-01, AT-S4-02
func TestV3_FieldBoundaryAmbiguity(t *testing.T) {
	mk := func(ver int, actor, action string) audit.Event {
		e := v3Ev(1, ver)
		e.Actor, e.Action = actor, action
		return e
	}
	if audit.ComputeEventHash("p", mk(3, "a|b", "c")) == audit.ComputeEventHash("p", mk(3, "a", "b|c")) {
		t.Fatal("v3 hashes must differ")
	}
	if audit.ComputeEventHash("p", mk(2, "a|b", "c")) != audit.ComputeEventHash("p", mk(2, "a", "b|c")) {
		t.Fatal("v2 formula must stay unchanged (documented weakness)")
	}
}

// AT-S4-03, AT-S4-07
func TestV3_WriterWritesV3AndBoundaryShiftDetected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	w, _ := audit.NewJSONLWriter(p)
	for i := 0; i < 2; i++ {
		if err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Resource: "x", Decision: "allow", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	b, _ := os.ReadFile(p)
	if strings.Count(string(b), `"schema_version":3`) != 2 {
		t.Fatalf("not all v3:\n%s", b)
	}
	if err := audit.VerifyHashChain(p); err != nil {
		t.Fatal(err)
	}
	ls := strings.Split(strings.TrimSpace(string(b)), "\n")
	ls[1] = strings.Replace(strings.Replace(ls[1], `"resource":"x"`, `"resource":"xa"`, 1), `"decision":"allow"`, `"decision":"llow"`, 1)
	_ = os.WriteFile(p, []byte(strings.Join(ls, "\n")+"\n"), 0o600)
	broken(t, audit.VerifyHashChain(p))
}

// AT-S4-04, AT-S4-05
func TestV3_MixedAndDowngrade(t *testing.T) {
	if err := audit.VerifyHashChain(chainLines(t, v3Ev(1, 1), v3Ev(2, 1), v3Ev(3, 1), v3Ev(4, 2), v3Ev(5, 2), v3Ev(6, 3), v3Ev(7, 3))); err != nil {
		t.Fatalf("mixed: %v", err)
	}
	broken(t, audit.VerifyHashChain(chainLines(t, v3Ev(1, 3), v3Ev(2, 2))))
	broken(t, audit.VerifyHashChain(chainLines(t, v3Ev(1, 3), v3Ev(2, 4))))
}

// AT-S4-06
func TestV3_CheckpointAcrossVersions(t *testing.T) {
	p := chainLines(t, v3Ev(1, 2), v3Ev(2, 2))
	dir := filepath.Dir(p)
	priv, pub, ck := filepath.Join(dir, "k.priv"), filepath.Join(dir, "k.pub"), filepath.Join(dir, "ck.json")
	if _, err := checkpoint.EnsureKeyPair(priv, pub, domain.RealClock{}); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpoint.Create(p, priv, pub, ck, domain.RealClock{}); err != nil {
		t.Fatal(err)
	}
	w, _ := audit.NewJSONLWriter(p)
	defer w.Close()
	if err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Success: true}); err != nil {
		t.Fatal(err)
	}
	if err := checkpoint.Verify(p, ck, pub); err != nil {
		t.Fatalf("checkpoint verify: %v", err)
	}
}
