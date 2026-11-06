package ui_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/ui"
)

func TestTimelineFormatter_RenderTimeline(t *testing.T) {
	var buf bytes.Buffer
	formatter := ui.NewTimelineFormatter(&buf)

	now := time.Date(2026, 11, 2, 16, 40, 1, 100000000, time.UTC)

	events := []audit.Event{
		{
			Timestamp: now,
			TraceID:   "tr-multihop-test",
			Step:      "orchestrator.spawn",
			Actor:     "orchestrator-main",
			Action:    "orchestrate",
			Success:   true,
			Decision:  "allow",
		},
		{
			Timestamp: now.Add(50 * time.Millisecond),
			TraceID:   "tr-multihop-test",
			Step:      "token.exchanged",
			Actor:     "client-subagent",
			Success:   true,
			Decision:  "allow",
			Metadata: map[string]interface{}{
				"delegation_depth": 1,
				"caller_id":        "orchestrator-main",
			},
		},
		{
			Timestamp: now.Add(100 * time.Millisecond),
			TraceID:   "tr-multihop-test",
			Step:      "pep.deny",
			Actor:     "worker-01",
			Action:    "file:write",
			Resource:  "secret.txt",
			Success:   false,
			Decision:  "deny",
			Reason:    "INSUFFICIENT_SCOPE",
			Metadata: map[string]interface{}{
				"exit_code": 12,
			},
		},
	}

	formatter.RenderTimeline("tr-multihop-test", true, events)
	out := buf.String()

	if !strings.Contains(out, "AUDIT TRACE TIMELINE: tr-multihop-test (Hash Chain: VALID)") {
		t.Errorf("missing valid header: %s", out)
	}
	if !strings.Contains(out, "orchestrator.spawn") {
		t.Errorf("missing orchestrator.spawn event: %s", out)
	}
	if !strings.Contains(out, "pep.deny") {
		t.Errorf("missing pep.deny event: %s", out)
	}
	if !strings.Contains(out, "Reason: INSUFFICIENT_SCOPE") {
		t.Errorf("missing Reason in deny event: %s", out)
	}
}

// 계획 015 B8: budget.consumed 줄도 타임라인에 오류 없이 보인다.
func TestTimelineFormatter_ShowsBudgetConsumed(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{Timestamp: now, TraceID: "tr-b", Step: "pep.budget_consume", Stage: "budget", Actor: "worker-01",
			Action: "budget.consumed", Resource: "docs/out.txt", Decision: "allow", Reason: "AUTHORIZED", Success: true},
	}
	ui.NewTimelineFormatter(&buf).RenderTimeline("tr-b", true, events)
	if !strings.Contains(buf.String(), "budget.consumed") && !strings.Contains(buf.String(), "pep.budget_consume") {
		t.Fatalf("타임라인에 budget.consumed 줄이 없음:\n%s", buf.String())
	}
}
