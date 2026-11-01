package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

func TestKeysRunner(t *testing.T) {
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, ".authz-state", "private", "signing_keys.priv.json")
	pubPath := filepath.Join(tmpDir, ".authz-state", "public", "jwks.pub.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	var stdout, stderr bytes.Buffer
	runner, err := NewKeysRunner(&stdout, &stderr, privPath, pubPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create KeysRunner: %v", err)
	}

	// 1. keys list 검증 (초기 자동 생성된 1개 active 키 존재)
	stdout.Reset()
	stderr.Reset()
	exitCode := runner.Run(context.Background(), []string{"list"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess for list, got %d. stderr: %s", exitCode, stderr.String())
	}
	outStr := stdout.String()
	if !strings.Contains(outStr, "KID") || !strings.Contains(outStr, "active") {
		t.Fatalf("expected active key in list output, got:\n%s", outStr)
	}

	// 2. keys rotate 검증
	stdout.Reset()
	stderr.Reset()
	exitCode = runner.Run(context.Background(), []string{"rotate", "--actor", "admin-tester", "--reason", "test rotation"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess for rotate, got %d. stderr: %s", exitCode, stderr.String())
	}
	rotateOut := stdout.String()
	if !strings.Contains(rotateOut, "Key rotated successfully") {
		t.Fatalf("unexpected rotate output:\n%s", rotateOut)
	}

	// 3. keys list 재확인: active 1개, verify-only 1개 존재해야 함
	stdout.Reset()
	stderr.Reset()
	exitCode = runner.Run(context.Background(), []string{"list"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess for list after rotation, got %d", exitCode)
	}
	outStr = stdout.String()
	if !strings.Contains(outStr, "verify-only") || !strings.Contains(outStr, "active") {
		t.Fatalf("expected both verify-only and active keys, got:\n%s", outStr)
	}

	// 구 키 KID 추출
	lines := strings.Split(strings.TrimSpace(outStr), "\n")
	var verifyOnlyKID string
	for _, line := range lines[1:] {
		if strings.Contains(line, "verify-only") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				verifyOnlyKID = fields[0]
			}
		}
	}
	if verifyOnlyKID == "" {
		t.Fatalf("failed to find verify-only kid from output:\n%s", outStr)
	}

	// 4. keys revoke 검증
	stdout.Reset()
	stderr.Reset()
	exitCode = runner.Run(context.Background(), []string{"revoke", "--kid", verifyOnlyKID, "--reason", "revoking old key"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess for revoke, got %d. stderr: %s", exitCode, stderr.String())
	}
	revokeOut := stdout.String()
	if !strings.Contains(revokeOut, "Key revoked successfully") {
		t.Fatalf("unexpected revoke output:\n%s", revokeOut)
	}

	// 5. keys list 재확인: retired 상태 확인
	stdout.Reset()
	stderr.Reset()
	exitCode = runner.Run(context.Background(), []string{"list"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess for list after revocation, got %d", exitCode)
	}
	outStr = stdout.String()
	if !strings.Contains(outStr, "retired") {
		t.Fatalf("expected retired status in list output, got:\n%s", outStr)
	}

	// 6. 존재하지 않는 키 폐기 시도 -> ExitBadInput
	stdout.Reset()
	stderr.Reset()
	exitCode = runner.Run(context.Background(), []string{"revoke", "--kid", "non-existent-kid"})
	if exitCode != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput for non-existent kid, got %d", exitCode)
	}
}
