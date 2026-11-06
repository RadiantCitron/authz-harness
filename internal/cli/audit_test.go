package cli_test

import (
	"bytes"
	"context"
	"os"
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
		Step:      "orchestrator.spawn",
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
	runner := cli.NewAuditRunner(&out, &errOut, auditFile, filepath.Join(t.TempDir(), "priv", "k.json"), filepath.Join(t.TempDir(), "pub", "j.json"))

	exitCode := runner.Run(context.Background(), []string{"timeline", "--trace-id", traceID})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}

	outStr := out.String()
	if !strings.Contains(outStr, "AUDIT TRACE TIMELINE: trace-timeline-test") {
		t.Errorf("missing header in output:\n%s", outStr)
	}
	if !strings.Contains(outStr, "orchestrator.spawn") || !strings.Contains(outStr, "pep.allow") {
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
	runner := cli.NewAuditRunner(&out, &errOut, auditFile, filepath.Join(t.TempDir(), "priv", "k.json"), filepath.Join(t.TempDir(), "pub", "j.json"))

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
	runner := cli.NewAuditRunner(&out, &errOut, auditFile, filepath.Join(t.TempDir(), "priv", "k.json"), filepath.Join(t.TempDir(), "pub", "j.json"))

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

func TestAuditCheckpointCLI(t *testing.T) { // TC-040-07
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.jsonl")
	w, err := audit.NewJSONLWriter(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "x", Success: true})
	}
	_ = w.Close()

	var out, errOut bytes.Buffer
	r := cli.NewAuditRunner(&out, &errOut, auditFile, filepath.Join(dir, "priv", "s.json"), filepath.Join(dir, "pub", "j.json"))
	if c := r.Run(context.Background(), []string{"checkpoint"}); c != domain.ExitSuccess {
		t.Fatalf("checkpoint: %v %s", c, errOut.String())
	}
	ck := filepath.Join(dir, "pub", "audit_checkpoint.json")
	if c := r.Run(context.Background(), []string{"verify", "--checkpoint", ck}); c != domain.ExitSuccess {
		t.Fatalf("verify: %v %s", c, out.String())
	}
	b, _ := os.ReadFile(auditFile)
	ls := strings.Split(strings.TrimSpace(string(b)), "\n")
	_ = os.WriteFile(auditFile, []byte(strings.Join(ls[:2], "\n")+"\n"), 0o600)
	if c := r.Run(context.Background(), []string{"verify", "--checkpoint", ck}); c != domain.ExitAuditFailure {
		t.Fatalf("truncated verify: %v", c)
	}
}

func TestAuditTreeCLI(t *testing.T) { // TC-050-05
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.jsonl")
	w, _ := audit.NewJSONLWriter(auditFile)
	_ = w.Log(audit.Event{TraceID: "tr-1", Actor: "o", Action: "token.exchanged", Success: true, Decision: "allow",
		Metadata: map[string]interface{}{"parent_jti": "pj", "parent_sub": "Root", "child_jti": "cj", "child_sub": "w1", "delegation_depth": 1}})
	_ = w.Close()

	var out, errOut bytes.Buffer
	r := cli.NewAuditRunner(&out, &errOut, auditFile, filepath.Join(dir, "p", "k"), filepath.Join(dir, "q", "j"))
	if c := r.Run(context.Background(), []string{"tree"}); c != domain.ExitSuccess || !strings.Contains(out.String(), "[w1] jti=cj depth=1") {
		t.Fatalf("latest: %v\n%s", c, out.String())
	}
	errOut.Reset()
	if c := r.Run(context.Background(), []string{"tree", "--trace-id", "nope"}); c != domain.ExitBadInput || !strings.Contains(errOut.String(), "no audit events found for trace ID") {
		t.Fatalf("missing: %v %s", c, errOut.String())
	}
}
