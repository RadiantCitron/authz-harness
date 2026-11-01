package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/audit"
)

func TestJSONLWriter_LogAndRead(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test_audit.jsonl")

	writer, err := audit.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create JSONLWriter: %v", err)
	}
	defer writer.Close()

	ev1 := audit.Event{
		TraceID:  "trace-1001",
		Step:     "010",
		Actor:    "orchestrator",
		Action:   "token.issue",
		Resource: "scope:file:read",
		Decision: "allow",
		Reason:   "valid orchestrator subject",
		Success:  true,
	}

	ev2 := audit.Event{
		TraceID:    "trace-1001",
		Step:       "020",
		Actor:      "subagent-01",
		Action:     "file:write",
		Resource:   "/etc/passwd",
		Decision:   "deny",
		Reason:     "path traversal attempt outside workspace jail",
		Success:    false,
		ErrorClass: "PATH_TRAVERSAL_DETECTED",
	}

	if err := writer.Log(ev1); err != nil {
		t.Fatalf("failed to log ev1: %v", err)
	}
	if err := writer.Log(ev2); err != nil {
		t.Fatalf("failed to log ev2: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}

	// 검증: 파일에서 한 줄씩 읽어 스키마 일치 확인
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var events []audit.Event
	for scanner.Scan() {
		var ev audit.Event
		line := scanner.Bytes()
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("failed to unmarshal JSON line: %v", err)
		}
		events = append(events, ev)
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// ev1 검증
	if events[0].TraceID != "trace-1001" || events[0].Decision != "allow" || !events[0].Success {
		t.Errorf("unexpected ev1: %+v", events[0])
	}
	if events[0].Timestamp.IsZero() {
		t.Errorf("expected auto-populated timestamp, got zero")
	}

	// ev2 검증
	if events[1].Decision != "deny" || events[1].ErrorClass != "PATH_TRAVERSAL_DETECTED" || events[1].Success {
		t.Errorf("unexpected ev2: %+v", events[1])
	}
}

func TestJSONLWriter_ConcurrentSafety(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "concurrent_audit.jsonl")

	writer, err := audit.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}
	defer writer.Close()

	numRoutines := 10
	eventsPerRoutine := 20
	done := make(chan bool, numRoutines)

	for i := 0; i < numRoutines; i++ {
		go func(routineID int) {
			for j := 0; j < eventsPerRoutine; j++ {
				_ = writer.Log(audit.Event{
					TraceID: "concurrent-trace",
					Actor:   "worker",
					Success: true,
					Timestamp: time.Now().UTC(),
				})
			}
			done <- true
		}(i)
	}

	for i := 0; i < numRoutines; i++ {
		<-done
	}

	writer.Close()

	// 라인 수 검증
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer f.Close()

	lineCount := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineCount++
	}

	expected := numRoutines * eventsPerRoutine
	if lineCount != expected {
		t.Errorf("expected %d lines, got %d", expected, lineCount)
	}
}
