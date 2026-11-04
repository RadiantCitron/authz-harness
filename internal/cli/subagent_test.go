package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/subagent"
)

func TestSubagentRunner_TC01_NormalRead(t *testing.T) {
	rig := setupPEPCLITestRig(t)

	// 준비: Grant 및 파일 생성
	testFile := "readable.txt"
	absPath := filepath.Join(rig.workspaceDir, testFile)
	if err := os.WriteFile(absPath, []byte("subagent content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	sub := "subagent-alice"
	rig.createGrant(t, sub, "operator", "file:read", testFile)

	tokenStr := rig.issueToken(t, sub, "file:read", "authz-harness")

	runner, err := NewSubagentRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create subagent runner: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-cli-01",
		Token:    tokenStr,
		Action:   "file:read",
		FilePath: testFile,
	}
	inBuf := &bytes.Buffer{}
	_ = json.NewEncoder(inBuf).Encode(req)
	runner.SetStdin(inBuf)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{"worker"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got: %d (stderr: %s)", exitCode, rig.errOut.String())
	}

	var resp subagent.SubagentResponse
	if err := json.Unmarshal(rig.out.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v, raw: %s", err, rig.out.String())
	}

	if resp.ExitCode != int(domain.ExitSuccess) {
		t.Errorf("expected resp.ExitCode 0, got %d", resp.ExitCode)
	}
	if resp.Output != "subagent content" {
		t.Errorf("expected resp.Output 'subagent content', got %q", resp.Output)
	}
}

func TestSubagentRunner_TC02_InvalidJSONFrame(t *testing.T) {
	rig := setupPEPCLITestRig(t)

	runner, err := NewSubagentRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create subagent runner: %v", err)
	}

	inBuf := bytes.NewBufferString("{broken-json-frame")
	runner.SetStdin(inBuf)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{"worker"})
	if exitCode != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput(2), got: %d", exitCode)
	}

	var resp subagent.SubagentResponse
	_ = json.Unmarshal(rig.out.Bytes(), &resp)
	if resp.ExitCode != int(domain.ExitBadInput) {
		t.Errorf("expected ExitBadInput in json, got %d", resp.ExitCode)
	}
}

func TestSubagentRunner_TC03_InvalidToken(t *testing.T) {
	rig := setupPEPCLITestRig(t)

	runner, err := NewSubagentRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create subagent runner: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-cli-03",
		Token:    "invalid.jwt.token",
		Action:   "file:read",
		FilePath: "file.txt",
	}
	inBuf := &bytes.Buffer{}
	_ = json.NewEncoder(inBuf).Encode(req)
	runner.SetStdin(inBuf)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{"worker"})
	if exitCode != domain.ExitTokenInvalid {
		t.Fatalf("expected ExitTokenInvalid(11), got: %d", exitCode)
	}
}

func TestSubagentRunner_TC04_AuthzDenied(t *testing.T) {
	rig := setupPEPCLITestRig(t)

	sub := "subagent-bob"
	tokenStr := rig.issueToken(t, sub, "file:read", "authz-harness")

	runner, err := NewSubagentRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create subagent runner: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-cli-04",
		Token:    tokenStr,
		Action:   "file:write",
		FilePath: "unauthorized.txt",
		Data:     "forbidden data",
	}
	inBuf := &bytes.Buffer{}
	_ = json.NewEncoder(inBuf).Encode(req)
	runner.SetStdin(inBuf)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{"worker"})
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied(12), got: %d", exitCode)
	}

	// 파일 미생성 0바이트 검증
	targetPath := filepath.Join(rig.workspaceDir, "unauthorized.txt")
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Errorf("file should not exist on authz denial")
	}
}

func TestSubagentRunner_TC05_PathViolation(t *testing.T) {
	rig := setupPEPCLITestRig(t)

	// Workspace 내부에 외부를 가리키는 symlink 생성하여 심볼릭 링크 기반 탈출 시도
	outsideFile := filepath.Join(t.TempDir(), "target_outside.txt")
	_ = os.WriteFile(outsideFile, []byte("outside content"), 0644)
	symlinkPath := filepath.Join(rig.workspaceDir, "escape_link.txt")
	_ = os.Symlink(outsideFile, symlinkPath)

	sub := "subagent-charlie"
	rig.createGrant(t, sub, "operator", "file:read", "escape_link.txt")
	tokenStr := rig.issueToken(t, sub, "file:read", "authz-harness")

	runner, err := NewSubagentRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create subagent runner: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-cli-05",
		Token:    tokenStr,
		Action:   "file:read",
		FilePath: "escape_link.txt",
	}
	inBuf := &bytes.Buffer{}
	_ = json.NewEncoder(inBuf).Encode(req)
	runner.SetStdin(inBuf)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{"worker"})
	if exitCode != domain.ExitPathViolation {
		t.Fatalf("expected ExitPathViolation(13), got: %d", exitCode)
	}
}

func TestSubagentRunner_SubcommandValidation(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	runner, _ := NewSubagentRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)

	if code := runner.Run(context.Background(), []string{}); code != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput for empty args, got %d", code)
	}
	if code := runner.Run(context.Background(), []string{"unknown"}); code != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput for unknown subcmd, got %d", code)
	}
	if code := runner.Run(context.Background(), []string{"worker", "-invalid-flag"}); code != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput for invalid flag, got %d", code)
	}
}

// 로드맵 16 / 040 TC-040-12: -net-allow 검증
func TestSubagentRunner_NetAllowFlag(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	runner, err := NewSubagentRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatal(err)
	}

	runner.SetStdin(bytes.NewBufferString("{}"))
	if c := runner.Run(context.Background(), []string{"worker", "-net-allow", "evil:80"}); c != domain.ExitBadInput {
		t.Fatalf("invalid -net-allow: expected 14, got %d", c)
	}

	rig.out.Reset()
	runner.SetStdin(bytes.NewBufferString("{broken"))
	c := runner.Run(context.Background(), []string{"worker", "-net-allow", "127.0.0.1:18080,[::1]:18080"})
	// 정상 기동: 스택이 조립되어 JSON 프레임 단계(입력 오류 14, 응답 JSON 존재)까지 도달한다.
	var resp subagent.SubagentResponse
	if c != domain.ExitBadInput || json.Unmarshal(rig.out.Bytes(), &resp) != nil || resp.Reason != string(domain.ReasonInvalidArguments) {
		t.Fatalf("valid -net-allow must boot to frame parsing: code=%d out=%q", c, rig.out.String())
	}
}
