package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
	"authz-harness/internal/subagent"
)

// TestHelperProcess 는 os/exec 자식 프로세스로 실행되어 모의 서브에이전트 동작을 수행한다.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	mode := os.Getenv("HELPER_MODE")
	switch mode {
	case "sleep":
		time.Sleep(1 * time.Second)
		os.Exit(0)

	case "exit_11":
		resp := subagent.SubagentResponse{
			TraceID:  "tr-test",
			ExitCode: 11,
			Error:    "token invalid",
			Reason:   "INVALID_TOKEN",
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(11)

	case "exit_12":
		resp := subagent.SubagentResponse{
			TraceID:  "tr-test",
			ExitCode: 12,
			Error:    "access denied",
			Reason:   "INSUFFICIENT_SCOPE",
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(12)

	case "exit_13":
		resp := subagent.SubagentResponse{
			TraceID:  "tr-test",
			ExitCode: 13,
			Error:    "escape violation",
			Reason:   "PATH_ESCAPE",
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(13)

	default:
		// stdin 프레임을 읽어 그대로 성공 응답 생성
		var req subagent.SubagentRequest
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			fmt.Fprintf(os.Stderr, "failed to decode req: %v\n", err)
			os.Exit(1)
		}

		resp := subagent.SubagentResponse{
			TraceID:      req.TraceID,
			ExitCode:     0,
			Action:       req.Action,
			FilePath:     req.FilePath,
			BytesRead:    len(req.Data),
			BytesWritten: 0,
			Output:       "mock-content",
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(0)
	}
}

// TC-01: 화이트리스트 환경변수 보존
func TestTC01_AllowedEnvPreserved(t *testing.T) {
	inputEnv := []string{
		"PATH=/usr/bin:/bin",
		"TMPDIR=/tmp",
		"HOME=/var/empty", // public-safety: allow test path
		"USER=testuser",
		"LANG=en_US.UTF-8",
		"LC_ALL=C",
	}

	sanitized := SanitizeEnv(inputEnv)
	if len(sanitized) != len(inputEnv) {
		t.Fatalf("expected all %d allowed vars to be preserved, got %d: %v", len(inputEnv), len(sanitized), sanitized)
	}
}

// TC-02: 민감/금지 환경변수 차단
func TestTC02_BlockedEnvFiltered(t *testing.T) {
	inputEnv := []string{
		"PATH=/usr/bin",
		"ZONE_A_KEY_PATH=/secrets/key.pem",
		"SECRET_TOKEN=supersecret",
		"AUTHZ_KEY_SECRET=privkey",
		"GO_ENV=production",
		"DEBUG=true",
		"RANDOM_UNLISTED_VAR=someval",
	}

	sanitized := SanitizeEnv(inputEnv)
	for _, env := range sanitized {
		for _, prefix := range BlockedEnvPrefixes {
			if len(env) >= len(prefix) && env[:len(prefix)] == prefix {
				t.Fatalf("blocked env prefix %q found in sanitized env: %s", prefix, env)
			}
		}
		if env == "RANDOM_UNLISTED_VAR=someval" {
			t.Fatalf("unlisted var should have been excluded, but found: %s", env)
		}
	}

	if len(sanitized) != 1 || sanitized[0] != "PATH=/usr/bin" {
		t.Fatalf("expected only PATH to be preserved, got %v", sanitized)
	}
}

// helperSpawnerForTest 는 TestHelperProcess 를 실행할 수 있는 Spawner 인스턴스를 생성한다.
func helperSpawnerForTest(t *testing.T, mode string, timeout time.Duration, auditWriter audit.Writer) *SubprocessSpawner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable: %v", err)
	}

	cfg := SpawnConfig{
		BinaryPath: exe,
		Args:       []string{"-test.run=TestHelperProcess", "--"},
		Timeout:    timeout,
		Audit:      auditWriter,
		ExtraEnv: []string{
			"GO_WANT_HELPER_PROCESS=1",
			fmt.Sprintf("HELPER_MODE=%s", mode),
		},
	}

	spawner, err := NewSubprocessSpawner(cfg)
	if err != nil {
		t.Fatalf("failed to create spawner: %v", err)
	}
	return spawner
}

// TC-03: 정상 서브에이전트 스폰 및 성공 수거
func TestTC03_SpawnSuccess(t *testing.T) {
	spawner := helperSpawnerForTest(t, "normal", 5*time.Second, nil)

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-tc03-success",
		Token:    "sample.jwt.token",
		Action:   "file:read",
		FilePath: "data/input.txt",
	}

	res, err := spawner.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("spawn returned error: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Response == nil {
		t.Fatalf("expected response frame, got nil")
	}
	if res.Response.ExitCode != 0 {
		t.Errorf("expected response exit code 0, got %d", res.Response.ExitCode)
	}
	if res.Response.Output != "mock-content" {
		t.Errorf("expected output 'mock-content', got %q", res.Response.Output)
	}
	if res.Duration <= 0 {
		t.Errorf("expected duration > 0, got %v", res.Duration)
	}
}

// TC-04: 서브에이전트 인가 거부(12) 수거
func TestTC04_SpawnExit12(t *testing.T) {
	spawner := helperSpawnerForTest(t, "exit_12", 5*time.Second, nil)

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-tc04-exit12",
		Token:    "token.insufficient.scope",
		Action:   "file:write",
		FilePath: "data/write.txt",
	}

	res, err := spawner.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("spawn returned error: %v", err)
	}

	if res.ExitCode != 12 {
		t.Errorf("expected exit code 12, got %d", res.ExitCode)
	}
	if res.Response == nil || res.Response.ExitCode != 12 {
		t.Errorf("expected parsed response with exit code 12, got %+v", res.Response)
	}
}

// TC-05: 서브에이전트 탈출 위반(13) 수거
func TestTC05_SpawnExit13(t *testing.T) {
	spawner := helperSpawnerForTest(t, "exit_13", 5*time.Second, nil)

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-tc05-exit13",
		Token:    "valid.token",
		Action:   "file:read",
		FilePath: "../../../etc/passwd",
	}

	res, err := spawner.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("spawn returned error: %v", err)
	}

	if res.ExitCode != 13 {
		t.Errorf("expected exit code 13, got %d", res.ExitCode)
	}
	if res.Response == nil || res.Response.Reason != "PATH_ESCAPE" {
		t.Errorf("expected reason PATH_ESCAPE, got %+v", res.Response)
	}
}

// TC-06: 서브에이전트 토큰 무효(11) 수거
func TestTC06_SpawnExit11(t *testing.T) {
	spawner := helperSpawnerForTest(t, "exit_11", 5*time.Second, nil)

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-tc06-exit11",
		Token:    "invalid.forged.token",
		Action:   "file:read",
		FilePath: "data/input.txt",
	}

	res, err := spawner.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("spawn returned error: %v", err)
	}

	if res.ExitCode != 11 {
		t.Errorf("expected exit code 11, got %d", res.ExitCode)
	}
	if res.Response == nil || res.Response.ExitCode != 11 {
		t.Errorf("expected response exit code 11, got %+v", res.Response)
	}
}

// TC-07: 입력 검증 (TraceID 누락)
func TestTC07_TraceIDRequired(t *testing.T) {
	spawner := helperSpawnerForTest(t, "normal", 5*time.Second, nil)

	req := subagent.SubagentRequest{
		TraceID:  "", // 누락
		Token:    "some.token",
		Action:   "file:read",
		FilePath: "data/input.txt",
	}

	_, err := spawner.Spawn(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on empty trace_id, got nil")
	}
}

// readAuditEvents 는 주어진 경로의 audit.jsonl 파일에서 이벤트들을 읽어온다.
func readAuditEvents(path string) ([]audit.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []audit.Event
	dec := json.NewDecoder(f)
	for dec.More() {
		var ev audit.Event
		if err := dec.Decode(&ev); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, nil
}

// TC-08: 부모 감사 연쇄 검증
func TestTC08_AuditChain(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("failed to create audit writer: %v", err)
	}
	defer auditWriter.Close()

	spawner := helperSpawnerForTest(t, "normal", 5*time.Second, auditWriter)

	traceID := "tr-tc08-audit-chain"
	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  traceID,
		Token:    "valid.jwt.token",
		Action:   "file:read",
		FilePath: "data/test.txt",
	}

	res, err := spawner.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("spawn failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}

	events, err := readAuditEvents(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit events: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(events))
	}

	if events[0].Step != "ORCHESTRATE_SPAWN" || events[0].TraceID != traceID {
		t.Errorf("unexpected event 0: %+v", events[0])
	}
	if events[1].Step != "ORCHESTRATE_COLLECT" || events[1].TraceID != traceID || !events[1].Success {
		t.Errorf("unexpected event 1: %+v", events[1])
	}
}

// TC-09: 컨텍스트 타임아웃 차단
func TestTC09_TimeoutKill(t *testing.T) {
	// 헬퍼는 1초 sleep, 타임아웃은 50ms로 강제 설정
	spawner := helperSpawnerForTest(t, "sleep", 50*time.Millisecond, nil)

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-tc09-timeout",
		Token:    "token",
		Action:   "file:read",
		FilePath: "data/input.txt",
	}

	res, err := spawner.Spawn(context.Background(), req)
	if err != nil {
		t.Fatalf("spawn returned unexpected err: %v", err)
	}

	if !res.TimedOut {
		t.Errorf("expected TimedOut true, got false")
	}
	if res.ExitCode == 0 {
		t.Errorf("expected non-zero exit code on timeout, got %d", res.ExitCode)
	}
}

// TC-10: 다중 동시 스폰 안정성 (-race 검증)
func TestTC10_ConcurrentSpawns(t *testing.T) {
	spawner := helperSpawnerForTest(t, "normal", 5*time.Second, nil)

	concurrency := 10
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := subagent.SubagentRequest{
				Version:  "1.0",
				TraceID:  fmt.Sprintf("tr-tc10-%d", idx),
				Token:    "token",
				Action:   "file:read",
				FilePath: fmt.Sprintf("data/file-%d.txt", idx),
			}

			res, err := spawner.Spawn(context.Background(), req)
			if err != nil {
				errCh <- fmt.Errorf("[%d] spawn error: %w", idx, err)
				return
			}
			if res.ExitCode != 0 {
				errCh <- fmt.Errorf("[%d] expected exit 0, got %d", idx, res.ExitCode)
				return
			}
			if res.TraceID != req.TraceID {
				errCh <- fmt.Errorf("[%d] trace_id mismatch: %s != %s", idx, res.TraceID, req.TraceID)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrency error: %v", err)
	}
}

// TC-010-03: Spawner.Spawn 호출 시 사전 감사 기록 실패 시 서브프로세스가 실행되지 않고 ExitAuditFailure 반환
type mockFailingAuditWriter struct{}

func (mockFailingAuditWriter) Log(ev audit.Event) error {
	return errors.New("injected audit write failure")
}

func (mockFailingAuditWriter) Close() error {
	return nil
}

func TestSpawner_FailClosedOnAuditError(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "should_not_exist.txt")

	spawner, err := NewSubprocessSpawner(SpawnConfig{
		BinaryPath: "/bin/sh",
		Args:       []string{"-c", fmt.Sprintf("echo 'created' > %s", outPath)},
		Timeout:    2 * time.Second,
		Audit:      mockFailingAuditWriter{},
	})
	if err != nil {
		t.Fatalf("NewSubprocessSpawner failed: %v", err)
	}

	req := subagent.SubagentRequest{
		TraceID:  "trace-audit-fail",
		Action:   "write",
		FilePath: outPath,
	}

	result, err := spawner.Spawn(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from Spawn when audit fails, got nil")
	}
	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}

	var dErr *domain.Error
	if !errors.As(err, &dErr) {
		t.Fatalf("expected *domain.Error, got %T: %v", err, err)
	}
	if dErr.ExitCode != domain.ExitAuditFailure {
		t.Fatalf("expected ExitCode %d (ExitAuditFailure), got %d", domain.ExitAuditFailure, dErr.ExitCode)
	}

	// 서브프로세스가 실제로 실행되지 않아 파일이 생성되지 않았음을 보장
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatal("fail-closed violated: subprocess ran and created file despite audit failure")
	}
}
