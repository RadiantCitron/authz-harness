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

func setupPDPCliTest(t *testing.T) (string, string) {
	t.Helper()
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")
	auditPath := filepath.Join(tempDir, "audit.jsonl")
	return statePath, auditPath
}

func TestPDP_CLI_Decide_And_Explain(t *testing.T) {
	ctx := context.Background()
	statePath, auditPath := setupPDPCliTest(t)

	var grantOut, grantErr bytes.Buffer
	grantRunner, err := cli.NewGrantRunner(&grantOut, &grantErr, statePath, auditPath)
	if err != nil {
		t.Fatalf("failed to create grant runner: %v", err)
	}

	// 1. 초기 상태: worker-01에 대해 docs/plan.txt 파일 읽기 인가 전 decide 질의 -> DENY (12)
	var out1, err1 bytes.Buffer
	pdpRunner1, err := cli.NewPDPRunner(&out1, &err1, statePath, auditPath)
	if err != nil {
		t.Fatalf("failed to create pdp runner: %v", err)
	}

	exitCode := pdpRunner1.Run(ctx, []string{"decide", "--sub", "worker-01", "--action", "file:read", "--resource", "docs/plan.txt"})
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied (12), got %d. stderr: %s", exitCode, err1.String())
	}
	if !strings.Contains(out1.String(), "[DECISION: DENY]") || !strings.Contains(out1.String(), "NO_ACTIVE_GRANT") {
		t.Errorf("unexpected output: %s", out1.String())
	}

	// 2. Grant 발급
	exitCode = grantRunner.Run(ctx, []string{"create", "--sub", "worker-01", "--action", "file:read", "--resource", "docs/plan.txt"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("failed to create grant: %d, stderr: %s", exitCode, grantErr.String())
	}

	// 3. 발급 후 decide 질의 -> ALLOW (0)
	var out2, err2 bytes.Buffer
	pdpRunner2, _ := cli.NewPDPRunner(&out2, &err2, statePath, auditPath)
	exitCode = pdpRunner2.Run(ctx, []string{"decide", "--sub", "worker-01", "--action", "file:read", "--resource", "docs/plan.txt"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d. stderr: %s", exitCode, err2.String())
	}
	if !strings.Contains(out2.String(), "[DECISION: ALLOW]") || !strings.Contains(out2.String(), "AUTHORIZED") {
		t.Errorf("unexpected output: %s", out2.String())
	}

	// 4. Grant ID 추출 및 회수
	createdStr := grantOut.String()
	idx := strings.Index(createdStr, "ID: grant-")
	if idx == -1 {
		t.Fatalf("could not find grant ID in output: %s", createdStr)
	}
	rawID := createdStr[idx+4:]
	endIdx := strings.Index(rawID, " |")
	if endIdx == -1 {
		t.Fatalf("could not find end of grant ID: %s", rawID)
	}
	grantID := strings.TrimSpace(rawID[:endIdx])

	exitCode = grantRunner.Run(ctx, []string{"revoke", "--id", grantID})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("failed to revoke grant: %d", exitCode)
	}

	// 5. 회수 후 decide 질의 -> GRANT_REVOKED (12)
	var out3, err3 bytes.Buffer
	pdpRunner3, _ := cli.NewPDPRunner(&out3, &err3, statePath, auditPath)
	exitCode = pdpRunner3.Run(ctx, []string{"decide", "--sub", "worker-01", "--action", "file:read", "--resource", "docs/plan.txt"})
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied (12), got %d", exitCode)
	}
	if !strings.Contains(out3.String(), "[DECISION: DENY]") || !strings.Contains(out3.String(), "GRANT_REVOKED") {
		t.Errorf("unexpected output: %s", out3.String())
	}

	// 6. explain 뷰 검증 -> 0 종료 및 상세 안내 출력
	var out4, err4 bytes.Buffer
	pdpRunner4, _ := cli.NewPDPRunner(&out4, &err4, statePath, auditPath)
	exitCode = pdpRunner4.Run(ctx, []string{"explain", "--sub", "worker-01", "--action", "file:read", "--resource", "docs/plan.txt"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0) for explain, got %d", exitCode)
	}
	explainOutput := out4.String()
	if !strings.Contains(explainOutput, "AUTHZ PIPELINE VERIFICATION REPORT") {
		t.Errorf("missing pipeline header in explain: %s", explainOutput)
	}
	if !strings.Contains(explainOutput, "부정 테스트 역설 해소") {
		t.Errorf("missing negative test explanation box: %s", explainOutput)
	}
	if !strings.Contains(explainOutput, "GRANT_REVOKED") {
		t.Errorf("missing reason in explain output: %s", explainOutput)
	}

	// 7. Security Epoch 일괄 무효화 검증
	// worker-02에게 Grant 발급 후 bump-epoch
	grantRunner.Run(ctx, []string{"create", "--sub", "worker-02", "--action", "file:write", "--resource", "data/out.txt"})
	grantRunner.Run(ctx, []string{"bump-epoch", "--sub", "worker-02"}) // Epoch 2

	var out5, err5 bytes.Buffer
	pdpRunner5, _ := cli.NewPDPRunner(&out5, &err5, statePath, auditPath)
	// 이전 Epoch(1)로 질의 시 SUBJECT_EPOCH_REVOKED 거부 (12)
	exitCode = pdpRunner5.Run(ctx, []string{"decide", "--sub", "worker-02", "--action", "file:write", "--resource", "data/out.txt", "--epoch", "1"})
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied (12), got %d", exitCode)
	}
	if !strings.Contains(out5.String(), "SUBJECT_EPOCH_REVOKED") {
		t.Errorf("expected SUBJECT_EPOCH_REVOKED, got: %s", out5.String())
	}

	// 8. 필수 인자 누락 검증 -> ExitBadInput (14)
	var out6, err6 bytes.Buffer
	pdpRunner6, _ := cli.NewPDPRunner(&out6, &err6, statePath, auditPath)
	exitCode = pdpRunner6.Run(ctx, []string{"decide", "--sub", "worker-01"})
	if exitCode != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput (14), got %d", exitCode)
	}
}

func TestTC_020_09_ScopeFlag(t *testing.T) {
	ctx := context.Background()
	statePath, auditPath := setupPDPCliTest(t)

	var grantOut, grantErr bytes.Buffer
	grantRunner, err := cli.NewGrantRunner(&grantOut, &grantErr, statePath, auditPath)
	if err != nil {
		t.Fatalf("failed to create grant runner: %v", err)
	}

	// 1. Grant 발급: worker-01에게 file:write on a.txt
	exitCode := grantRunner.Run(ctx, []string{"create", "--sub", "worker-01", "--action", "file:write", "--resource", "a.txt"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("failed to create grant: %d, stderr: %s", exitCode, grantErr.String())
	}

	// 2. pdp decide with --scope file:read -> ExitAuthzDenied (12), TOKEN_INSUFFICIENT_SCOPE
	var out1, err1 bytes.Buffer
	pdpRunner1, _ := cli.NewPDPRunner(&out1, &err1, statePath, auditPath)
	exitCode = pdpRunner1.Run(ctx, []string{
		"decide",
		"--sub", "worker-01",
		"--action", "file:write",
		"--resource", "a.txt",
		"--scope", "file:read",
	})
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied (12), got %d, stderr: %s", exitCode, err1.String())
	}
	if !strings.Contains(out1.String(), "[DECISION: DENY]") || !strings.Contains(out1.String(), string(domain.ReasonTokenInsufficientScope)) {
		t.Errorf("expected DENY and TOKEN_INSUFFICIENT_SCOPE, got: %s", out1.String())
	}

	// 3. pdp decide with matching --scope file:write -> ExitSuccess (0), AUTHORIZED
	var out2, err2 bytes.Buffer
	pdpRunner2, _ := cli.NewPDPRunner(&out2, &err2, statePath, auditPath)
	exitCode = pdpRunner2.Run(ctx, []string{
		"decide",
		"--sub", "worker-01",
		"--action", "file:write",
		"--resource", "a.txt",
		"--scope", "file:write:a.txt",
	})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %d, stderr: %s", exitCode, err2.String())
	}
	if !strings.Contains(out2.String(), "[DECISION: ALLOW]") || !strings.Contains(out2.String(), "AUTHORIZED") {
		t.Errorf("expected ALLOW and AUTHORIZED, got: %s", out2.String())
	}
}
