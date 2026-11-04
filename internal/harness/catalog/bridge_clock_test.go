package catalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/subagent"
)

// TestInProcBridgeClockOffset 은 TC-010-04: 인프로세스 브리지가 서브프로세스 워커와
// 같은 오프셋 판정(양수 만료 → 11, 음수 → 14)을 내리는지 증명한다.
func TestInProcBridgeClockOffset(t *testing.T) {
	cases := []struct {
		name      string
		offsetSec int64
		want      domain.ExitCode
	}{
		{"오프셋 0은 성공", 0, domain.ExitSuccess},
		{"TTL(5분) 초과 301초는 TOKEN_EXPIRED", 301, domain.ExitTokenInvalid},
		{"음수 -1초는 ExitBadInput", -1, domain.ExitBadInput},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := harness.NewSandboxEnvironment(harness.SandboxConfig{BaseDir: t.TempDir()})
			if err != nil {
				t.Fatalf("sandbox: %v", err)
			}
			defer env.Cleanup()
			stack, err := setupHarnessStack(env)
			if err != nil {
				t.Fatalf("stack: %v", err)
			}
			defer stack.Close()

			if err := os.WriteFile(filepath.Join(env.WorkspaceDir, "task.txt"), []byte("x"), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			sub := "bridge-clock"
			if _, err := stack.PAP.CreateGrant(context.Background(), pap.CreateGrantRequest{
				Subject: sub, Action: domain.ActionFileRead, Resource: "task.txt",
			}); err != nil {
				t.Fatalf("grant: %v", err)
			}
			tok, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01",
				sub, "file:read:task.txt", 5*time.Minute, token.IssueOptions{})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}

			res, err := (&inProcSpawnerBridge{stack: stack}).Spawn(context.Background(), subagent.SubagentRequest{
				TraceID:            "tr-bridge-" + string(rune('a'+i)),
				Token:              tok,
				Action:             "file:read",
				FilePath:           "task.txt",
				ClockOffsetSeconds: tc.offsetSec,
			})
			if err != nil {
				t.Fatalf("spawn: %v", err)
			}
			if domain.ExitCode(res.ExitCode) != tc.want {
				t.Fatalf("exit = %d, want %d", res.ExitCode, tc.want)
			}
		})
	}
}
