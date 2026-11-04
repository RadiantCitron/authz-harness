package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func exch(i int, pj, ps, cj, cs string, depth int) audit.Event {
	return audit.Event{Timestamp: t0.Add(time.Duration(i) * time.Second), TraceID: "tr", Action: "token.exchanged", Decision: "allow",
		Metadata: map[string]interface{}{"parent_jti": pj, "parent_sub": ps, "child_jti": cj, "child_sub": cs, "delegation_depth": depth}}
}

func pep(i int, jti, sub, action, dec, reason string) audit.Event {
	return audit.Event{Timestamp: t0.Add(time.Duration(i) * time.Second), TraceID: "tr", TokenJTI: jti, AgentID: sub, Action: action, Decision: dec, Reason: reason}
}

func TestDelegationTree_TwoHopSerial(t *testing.T) { // TC-050-01
	evs := []audit.Event{
		pep(0, "jti-root-0001", "Root", "authn.verify", "allow", "AUTHORIZED"),
		exch(1, "jti-root-0001", "Root", "jti-lead-0001", "lead-01", 1),
		exch(2, "jti-lead-0001", "lead-01", "jti-work-0001", "worker-01", 2),
		pep(3, "jti-work-0001", "worker-01", "pep.deny", "deny", "INSUFFICIENT_SCOPE"),
	}
	roots := BuildDelegationTree(evs)
	if len(roots) != 1 || roots[0].Depth != 0 || roots[0].Children[0].Depth != 1 || roots[0].Children[0].Children[0].Depth != 2 {
		t.Fatalf("bad tree: %+v", roots)
	}
	var b bytes.Buffer
	NewTreeFormatter(&b).Render("tr", roots)
	out := b.String()
	if !strings.Contains(out, "pep.deny deny INSUFFICIENT_SCOPE") || !strings.Contains(out, "[worker-01] jti=jti-work depth=2") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestDelegationTree_Siblings(t *testing.T) { // TC-050-02
	evs := []audit.Event{
		pep(0, "jti-root", "Root", "authn.verify", "allow", ""),
		exch(1, "jti-root", "Root", "jti-a", "worker-A", 1),
		exch(2, "jti-root", "Root", "jti-b", "worker-B", 1),
	}
	roots := BuildDelegationTree(evs)
	if len(roots) != 1 || len(roots[0].Children) != 2 || roots[0].Children[0].Depth != 1 || roots[0].Children[1].Depth != 1 {
		t.Fatalf("bad tree")
	}
	var b bytes.Buffer
	NewTreeFormatter(&b).RenderNodes(roots)
	if !strings.Contains(b.String(), "├── [worker-A]") || !strings.Contains(b.String(), "└── [worker-B]") {
		t.Fatalf("output:\n%s", b.String())
	}
}

func TestDelegationTree_SameSubjectTwoNodes(t *testing.T) { // TC-050-03
	evs := []audit.Event{
		exch(1, "jti-p1", "P1", "jti-w1", "worker-01", 1),
		exch(2, "jti-p2", "P2", "jti-w2", "worker-01", 1),
	}
	roots := BuildDelegationTree(evs)
	if len(roots) != 2 || roots[0].Children[0].JTI == roots[1].Children[0].JTI {
		t.Fatalf("expected two roots with distinct worker nodes: %+v", roots)
	}
}

func TestDelegationTree_ExternalParent(t *testing.T) { // TC-050-04
	roots := BuildDelegationTree([]audit.Event{exch(1, "jti-ext", "Issuer", "jti-c", "child", 1)})
	if len(roots) != 1 || !roots[0].External || len(roots[0].Children) != 1 {
		t.Fatalf("bad: %+v", roots)
	}
	var b bytes.Buffer
	NewTreeFormatter(&b).RenderNodes(roots)
	if !strings.Contains(b.String(), "[jti: jti-ext] Issuer (trace 밖에서 발급)") {
		t.Fatalf("output:\n%s", b.String())
	}
}

func TestTimeline_SiblingTreeNotStaircase(t *testing.T) { // TC-050-06
	evs := []audit.Event{
		exch(1, "jti-root", "Root", "jti-a", "worker-A", 1),
		exch(2, "jti-root", "Root", "jti-b", "worker-B", 1),
	}
	var b bytes.Buffer
	NewTimelineFormatter(&b).RenderTimeline("tr", true, evs)
	out := b.String()
	if !strings.Contains(out, "├── [worker-A]") || !strings.Contains(out, "└── [worker-B]") || !strings.Contains(out, "Chronological Timeline:") {
		t.Fatalf("output:\n%s", out)
	}
}
