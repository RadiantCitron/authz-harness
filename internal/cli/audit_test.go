package cli_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/cli"
	"authz-harness/internal/domain"
)

// TC-040-01: authz-harness audit timeline --trace-id <valid-id> 정상 시각화
func TestAuditRunner_Timeline_Success(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := audit.NewJSONLWriter(auditFile)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	traceID := "trace-timeline-test"
	_ = writer.Log(audit.Event{
		Timestamp: time.Now(),
		TraceID:   traceID,
		Step:      "ORCHESTRATE_SPAWN",
		Actor:     "orchestrator-main",
		Action:    "spawn",
		Success:   true,
	})
	_ = writer.Log(audit.Event{
		Timestamp: time.Now().Add(50 * time.Millisecond),
		TraceID:   traceID,
		Step:      "pep.allow",
		Actor:     "worker-01",
		Action:    "file:read",
		Resource:  "hello.txt",
		Success:   true,
	})
	_ = writer.Close()

	var out, errOut bytes.Buffer
	runner := cli.NewAuditRunner(&out, &errOut, auditFile)

	exitCode := runner.Run(context.Background(), []string{"timeline", "--trace-id", traceID})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}

	outStr := out.String()
	if !strings.Contains(outStr, "AUDIT TRACE TIMELINE: trace-timeline-test") {
		t.Errorf("missing header in output:\n%s", outStr)
	}
	if !strings.Contains(outStr, "ORCHESTRATE_SPAWN") || !strings.Contains(outStr, "pep.allow") {
		t.Errorf("missing timeline events in output:\n%s", outStr)
	}
}

// TC-040-02: 존재하지 않는 trace-id 조회 시 에러 반환
func TestAuditRunner_Timeline_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := audit.NewJSONLWriter(auditFile)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}
	_ = writer.Log(audit.Event{
		Timestamp: time.Now(),
		TraceID:   "other-trace",
		Actor:     "test",
		Success:   true,
	})
	_ = writer.Close()

	var out, errOut bytes.Buffer
	runner := cli.NewAuditRunner(&out, &errOut, auditFile)

	exitCode := runner.Run(context.Background(), []string{"timeline", "--trace-id", "non-existent-trace"})
	if exitCode != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput (14), got %v", exitCode)
	}
	if !strings.Contains(errOut.String(), "no audit events found for trace ID") {
		t.Errorf("expected not found message, got: %s", errOut.String())
	}
}

// TC-040-03: 차단(DENY) 이벤트 포함 시 Reason 및 DENY 태그 표시
func TestAuditRunner_Timeline_DenyEvent(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	writer, err := audit.NewJSONLWriter(auditFile)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	traceID := "trace-deny-test"
	_ = writer.Log(audit.Event{
		Timestamp: time.Now(),
		TraceID:   traceID,
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
	})
	_ = writer.Close()

	var out, errOut bytes.Buffer
	runner := cli.NewAuditRunner(&out, &errOut, auditFile)

	exitCode := runner.Run(context.Background(), []string{"timeline", "--trace-id", traceID})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got %v", exitCode)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "DENY") {
		t.Errorf("expected DENY in output:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Reason: INSUFFICIENT_SCOPE") {
		t.Errorf("expected Reason in output:\n%s", outStr)
	}
}
