package cli_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/cli"
	"authz-harness/internal/domain"
)

func setupTestGrantRunner(t *testing.T) (*cli.GrantRunner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")
	auditPath := filepath.Join(tempDir, "audit.jsonl")

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	runner, err := cli.NewGrantRunner(out, errOut, statePath, auditPath)
	if err != nil {
		t.Fatalf("failed to create GrantRunner: %v", err)
	}

	return runner, out, errOut
}

func TestGrantRunner_CreateAndRevoke(t *testing.T) {
	ctx := context.Background()
	runner, out, errOut := setupTestGrantRunner(t)

	// 1. 정상 발급
	exitCode := runner.Run(ctx, []string{"create", "--sub", "worker-01", "--action", "file:read", "--resource", "docs/plan.txt"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d, errOut: %s", domain.ExitSuccess, exitCode, errOut.String())
	}
	stdoutStr := out.String()
	if !strings.Contains(stdoutStr, "[GRANT CREATED]") || !strings.Contains(stdoutStr, "worker-01") {
		t.Fatalf("unexpected stdout: %s", stdoutStr)
	}

	// 파싱해서 ID 추출
	parts := strings.Split(stdoutStr, "|")
	idPart := strings.TrimSpace(parts[0]) // "[GRANT CREATED] ID: grant-xxx"
	idTokens := strings.Split(idPart, "ID: ")
	if len(idTokens) < 2 {
		t.Fatalf("failed to parse grant ID from stdout: %s", stdoutStr)
	}
	grantID := strings.TrimSpace(idTokens[1])

	// 2. 정상 회수
	out.Reset()
	errOut.Reset()
	exitCode = runner.Run(ctx, []string{"revoke", "--id", grantID})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d, errOut: %s", domain.ExitSuccess, exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "[GRANT REVOKED]") || !strings.Contains(out.String(), grantID) {
		t.Fatalf("unexpected revoke stdout: %s", out.String())
	}
}

func TestGrantRunner_BadInput(t *testing.T) {
	ctx := context.Background()
	runner, _, errOut := setupTestGrantRunner(t)

	// 1. 서브커맨드 없음
	exitCode := runner.Run(ctx, []string{})
	if exitCode != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput(14), got %d", exitCode)
	}

	// 2. create 필수 플래그 누락
	errOut.Reset()
	exitCode = runner.Run(ctx, []string{"create", "--sub", "worker-01"})
	if exitCode != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput(14), got %d", exitCode)
	}

	// 3. create 액션 오류
	errOut.Reset()
	exitCode = runner.Run(ctx, []string{"create", "--sub", "worker-01", "--action", "file:delete", "--resource", "docs/test.txt"})
	if exitCode != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput(14), got %d", exitCode)
	}

	// 4. 경로 탈출(..) 방어
	errOut.Reset()
	exitCode = runner.Run(ctx, []string{"create", "--sub", "worker-01", "--action", "file:read", "--resource", "../secret.txt"})
	if exitCode != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput(14) on traversal, got %d", exitCode)
	}
}

func TestGrantRunner_BumpEpoch(t *testing.T) {
	ctx := context.Background()
	runner, out, errOut := setupTestGrantRunner(t)

	exitCode := runner.Run(ctx, []string{"bump-epoch", "--sub", "worker-01"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d, errOut: %s", domain.ExitSuccess, exitCode, errOut.String())
	}

	if !strings.Contains(out.String(), "[EPOCH BUMPED]") || !strings.Contains(out.String(), "Previous: 1 -> Current: 2") {
		t.Fatalf("unexpected epoch stdout: %s", out.String())
	}
}

func TestGrantRunner_List(t *testing.T) {
	ctx := context.Background()
	runner, out, errOut := setupTestGrantRunner(t)

	// 빈 목록 조회
	exitCode := runner.Run(ctx, []string{"list"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d, errOut: %s", domain.ExitSuccess, exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "No grants found.") {
		t.Fatalf("expected 'No grants found.', got: %s", out.String())
	}

	// Grant 1건 추가 후 목록 조회
	_ = runner.Run(ctx, []string{"create", "--sub", "worker-01", "--action", "file:read", "--resource", "docs/test.txt"})
	out.Reset()
	errOut.Reset()
	exitCode = runner.Run(ctx, []string{"list", "--sub", "worker-01"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected exit code %d, got %d, errOut: %s", domain.ExitSuccess, exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "Sub: worker-01") {
		t.Fatalf("expected grant in list, got: %s", out.String())
	}
}
