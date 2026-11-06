package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
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

// TC-030-01: 단일 이벤트 기록 시 해시 생성 (PrevHash == "", CurrHash != "")
func TestTC_030_01_SingleEventHashGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "single_event.jsonl")

	w, err := audit.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}
	defer w.Close()

	ev := audit.Event{
		TraceID:  "trc-01",
		Actor:    "worker-01",
		Action:   "file:read",
		Resource: "data.txt",
		Decision: "allow",
		Reason:   "AUTHORIZED",
		Success:  true,
	}

	if err := w.Log(ev); err != nil {
		t.Fatalf("failed to log: %v", err)
	}
	w.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var recorded audit.Event
	if err := json.Unmarshal(data, &recorded); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	if recorded.PrevHash != "" {
		t.Errorf("expected empty PrevHash for first event, got %q", recorded.PrevHash)
	}
	if len(recorded.CurrHash) != 64 {
		t.Errorf("expected 64-char SHA256 CurrHash, got %q (len %d)", recorded.CurrHash, len(recorded.CurrHash))
	}
	if err := audit.VerifyHashChain(logPath); err != nil {
		t.Errorf("VerifyHashChain failed on single valid event: %v", err)
	}
}

// TC-030-02: 연속 이벤트 해시 체인 연결 (E2.PrevHash == E1.CurrHash, E3.PrevHash == E2.CurrHash)
func TestTC_030_02_SequentialHashChain(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "chain.jsonl")

	w, err := audit.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}
	defer w.Close()

	events := []audit.Event{
		{TraceID: "trc-02", Actor: "worker-01", Action: "file:read", Resource: "a.txt", Decision: "allow", Reason: "AUTHORIZED", Success: true},
		{TraceID: "trc-02", Actor: "worker-01", Action: "file:write", Resource: "b.txt", Decision: "allow", Reason: "AUTHORIZED", Success: true},
		{TraceID: "trc-02", Actor: "worker-01", Action: "file:read", Resource: "secret.key", Decision: "deny", Reason: "NO_ACTIVE_GRANT", Success: false},
	}

	for i, ev := range events {
		if err := w.Log(ev); err != nil {
			t.Fatalf("failed to log event #%d: %v", i+1, err)
		}
	}
	w.Close()

	// 체인 무결성 공식 검증
	if err := audit.VerifyHashChain(logPath); err != nil {
		t.Fatalf("VerifyHashChain failed: %v", err)
	}

	// 개별 레코드 직접 확인
	lines, err := readLines(logPath)
	if err != nil {
		t.Fatalf("failed to read lines: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	var e1, e2, e3 audit.Event
	_ = json.Unmarshal([]byte(lines[0]), &e1)
	_ = json.Unmarshal([]byte(lines[1]), &e2)
	_ = json.Unmarshal([]byte(lines[2]), &e3)

	if e1.PrevHash != "" {
		t.Errorf("e1 PrevHash should be empty, got %q", e1.PrevHash)
	}
	if e2.PrevHash != e1.CurrHash {
		t.Errorf("e2 PrevHash (%q) != e1 CurrHash (%q)", e2.PrevHash, e1.CurrHash)
	}
	if e3.PrevHash != e2.CurrHash {
		t.Errorf("e3 PrevHash (%q) != e2 CurrHash (%q)", e3.PrevHash, e2.CurrHash)
	}
}

// TC-030-03: 파일 선두/중간 변조 시 적발 (가짜 줄 삽입 시 ReasonAuditIntegrityBroken, ExitCode 15)
func TestTC_030_03_TamperedFileDetection(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "tampered.jsonl")

	w, err := audit.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}
	_ = w.Log(audit.Event{TraceID: "trc-03", Actor: "worker", Action: "file:read", Decision: "allow", Reason: "AUTHORIZED", Success: true})
	_ = w.Close()

	// 1. 파일 선두에 가짜 줄 삽입
	content, _ := os.ReadFile(logPath)
	tampered := append([]byte(`{"tampered":"attack"}`+"\n"), content...)
	_ = os.WriteFile(logPath, tampered, 0600)

	err = audit.VerifyHashChain(logPath)
	if err == nil {
		t.Fatalf("expected VerifyHashChain to fail on tampered file, got nil")
	}

	reason := domain.ReasonFromError(err, "")
	if reason != domain.ReasonAuditIntegrityBroken {
		t.Errorf("expected ReasonAuditIntegrityBroken, got %q", reason)
	}
	exitCode := domain.ExitCodeFromError(err, 0)
	if exitCode != domain.ExitAuditFailure {
		t.Errorf("expected ExitAuditFailure (15), got %d", exitCode)
	}
}

// TC-030-04: 레코드 내용 1바이트 수정 적발
func TestTC_030_04_OneByteMutationDetection(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "mutation.jsonl")

	w, _ := audit.NewJSONLWriter(logPath)
	_ = w.Log(audit.Event{TraceID: "trc-04", Actor: "worker", Action: "file:read", Decision: "allow", Reason: "AUTHORIZED", Success: true})
	_ = w.Log(audit.Event{TraceID: "trc-04", Actor: "worker", Action: "file:write", Decision: "deny", Reason: "NO_ACTIVE_GRANT", Success: false})
	_ = w.Close()

	content, _ := os.ReadFile(logPath)
	// 2번째 레코드의 "deny"를 "allow"로 변조
	tamperedStr := strings.Replace(string(content), `"decision":"deny"`, `"decision":"allow"`, 1)
	_ = os.WriteFile(logPath, []byte(tamperedStr), 0600)

	err := audit.VerifyHashChain(logPath)
	if err == nil {
		t.Fatalf("expected VerifyHashChain to fail on mutated record, got nil")
	}
	reason := domain.ReasonFromError(err, "")
	if reason != domain.ReasonAuditIntegrityBroken {
		t.Errorf("expected ReasonAuditIntegrityBroken, got %q", reason)
	}
}

// TC-030-05: 다중 JSONLWriter 인스턴스 교차 기록 (별도 프로세스 시뮬레이션)
func TestTC_030_05_CrossInstanceLogging(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "cross_instance.jsonl")

	// 1. Writer A가 1줄 기록
	wA, err := audit.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create writer A: %v", err)
	}
	if err := wA.Log(audit.Event{TraceID: "trc-05", Actor: "proc-A", Action: "spawn", Decision: "allow", Reason: "AUTHORIZED", Success: true}); err != nil {
		t.Fatalf("writer A log failed: %v", err)
	}

	// 2. Writer B가 별도 인스턴스로 오픈하여 1줄 기록 (동일 파일)
	wB, err := audit.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create writer B: %v", err)
	}
	if err := wB.Log(audit.Event{TraceID: "trc-05", Actor: "proc-B", Action: "file:read", Decision: "allow", Reason: "AUTHORIZED", Success: true}); err != nil {
		t.Fatalf("writer B log failed: %v", err)
	}

	// 3. 다시 Writer A가 1줄 기록
	if err := wA.Log(audit.Event{TraceID: "trc-05", Actor: "proc-A", Action: "exit", Decision: "allow", Reason: "AUTHORIZED", Success: true}); err != nil {
		t.Fatalf("writer A second log failed: %v", err)
	}

	_ = wA.Close()
	_ = wB.Close()

	// 체인 무결성 확인
	if err := audit.VerifyHashChain(logPath); err != nil {
		t.Fatalf("VerifyHashChain failed on cross-instance file: %v", err)
	}
}

// TC-030-06: 20개 고루틴 동시 기록 (-race)
func TestTC_030_06_ConcurrentFlockSafety(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "concurrent_flock.jsonl")

	numRoutines := 20
	eventsPerRoutine := 5
	var wg sync.WaitGroup

	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			// 각 고루틴이 독자적인 Writer 인스턴스를 열어 기록 (다중 프로세스 시뮬레이션)
			writer, err := audit.NewJSONLWriter(logPath)
			if err != nil {
				t.Errorf("failed to open writer: %v", err)
				return
			}
			defer writer.Close()

			for j := 0; j < eventsPerRoutine; j++ {
				ev := audit.Event{
					TraceID:  "trc-concurrent",
					Actor:    "worker",
					Action:   "concurr.step",
					Decision: "allow",
					Reason:   "AUTHORIZED",
					Success:  true,
				}
				if err := writer.Log(ev); err != nil {
					t.Errorf("routine %d log #%d failed: %v", routineID, j, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()

	// 체인 검증
	if err := audit.VerifyHashChain(logPath); err != nil {
		t.Fatalf("VerifyHashChain failed on concurrent log file: %v", err)
	}

	lines, err := readLines(logPath)
	if err != nil {
		t.Fatalf("failed to read lines: %v", err)
	}
	expected := numRoutines * eventsPerRoutine
	if len(lines) != expected {
		t.Errorf("expected %d lines, got %d", expected, len(lines))
	}
}

// TC-030-07: 최상위 Decision·Reason 자동 승격
func TestTC_030_07_TopLevelFieldElevation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "elevation.jsonl")

	w, _ := audit.NewJSONLWriter(logPath)
	defer w.Close()

	ev := audit.Event{
		TraceID: "trc-07",
		Actor:   "worker-07",
		Action:  "authn.verified",
		Success: false,
		Metadata: map[string]interface{}{
			"reason":   "TOKEN_EXPIRED",
			"decision": "DENY",
		},
	}

	if err := w.Log(ev); err != nil {
		t.Fatalf("failed to log: %v", err)
	}
	w.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var recorded audit.Event
	if err := json.Unmarshal(data, &recorded); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	if recorded.Decision != "deny" {
		t.Errorf("expected top-level decision 'deny', got %q", recorded.Decision)
	}
	if recorded.Reason != "TOKEN_EXPIRED" {
		t.Errorf("expected top-level reason 'TOKEN_EXPIRED', got %q", recorded.Reason)
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}
