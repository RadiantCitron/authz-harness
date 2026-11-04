package subagent_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
	"authz-harness/internal/subagent"
)

// TestWorkerClockOffset 은 TC-010-01~03: 워커 프레임의 시계 오프셋이 PEP 까지 전달되고,
// 음수 오프셋은 PEP 호출 없이 ExitBadInput 으로 거부됨을 증명한다.
func TestWorkerClockOffset(t *testing.T) {
	const ttl = 5 * time.Minute

	cases := []struct {
		name       string
		offsetSec  int64
		wantExit   domain.ExitCode
		wantReason string
	}{
		{"TC-010-01 오프셋 0은 성공", 0, domain.ExitSuccess, "AUTHORIZED"},
		{"TC-010-02 TTL 초과 양수 오프셋은 만료 거부", 301, domain.ExitTokenInvalid, string(domain.ReasonTokenExpired)},
		{"TC-010-03 음수 오프셋은 PEP 미호출 거부", -360, domain.ExitBadInput, string(domain.ReasonInvalidArguments)},
		{"TC-010-03 음수 -1초도 거부", -1, domain.ExitBadInput, string(domain.ReasonInvalidArguments)},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setupSubagentFixture(t)
			sub := "worker-clock"
			grantPolicy(t, f, sub, domain.ActionFileRead, "task.txt")
			if err := os.WriteFile(filepath.Join(f.workspaceDir, "task.txt"), []byte("x"), 0644); err != nil {
				t.Fatalf("write task.txt: %v", err)
			}
			res, err := f.tokenIssuer.IssueToken(token.IssueRequest{
				ClientID:     "client-orchestrator",
				ClientSecret: "orchestrator-secret-key-01",
				Subject:      sub,
				Audience:     "authz-harness",
				Scope:        "file:read:task.txt",
				TTL:          ttl,
				Epoch:        1,
			}, token.IssueOptions{}, domain.AuditContext{TraceID: "issue", Actor: sub})
			if err != nil {
				t.Fatalf("issue token: %v", err)
			}

			resp, code := f.worker.Execute(context.Background(), subagent.SubagentRequest{
				Version:            "1.0",
				TraceID:            "tr-clock-" + string(rune('a'+i)),
				Token:              res.TokenString,
				Action:             "file:read",
				FilePath:           "task.txt",
				ClockOffsetSeconds: tc.offsetSec,
			})
			if domain.ExitCode(code) != tc.wantExit {
				t.Fatalf("exit = %d, want %d (resp=%+v)", code, tc.wantExit, resp)
			}
			if resp.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", resp.Reason, tc.wantReason)
			}
		})
	}
}
