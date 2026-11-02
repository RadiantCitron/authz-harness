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
			Step:      "ORCHESTRATE_SPAWN",
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
	if !strings.Contains(out, "ORCHESTRATE_SPAWN") {
		t.Errorf("missing ORCHESTRATE_SPAWN event: %s", out)
	}
	if !strings.Contains(out, "pep.deny") {
		t.Errorf("missing pep.deny event: %s", out)
	}
	if !strings.Contains(out, "Reason: INSUFFICIENT_SCOPE") {
		t.Errorf("missing Reason in deny event: %s", out)
	}
}
