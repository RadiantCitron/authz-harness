package catalog

import (
	"context"
	"testing"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

func newSessionRig(t *testing.T) (*harness.SandboxEnvironment, *harnessStack, *SessionDriver, string, *domain.Grant) {
	t.Helper()
	env, err := harness.NewSandboxEnvironment(harness.SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	t.Cleanup(func() { env.Cleanup() })
	stack, err := setupHarnessStack(env)
	if err != nil {
		t.Fatalf("stack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	if err := writeFixture(env, "s.txt", "hello"); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	g, err := grantPermission(context.Background(), stack, "sess-sub", domain.ActionFileRead, "s.txt")
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	res, err := issueBudgetRoot(stack, "sess-sub", "file:read:s.txt", 5*time.Minute, domain.Budget{MaxCalls: 5})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	d, err := NewSessionDriver(context.Background(), env, stack)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return env, stack, d, res.TokenString, g
}

func TestSessionDriver(t *testing.T) {
	read := map[string]any{"path": "s.txt"}

	t.Run("TC-020-01 시간 전진 후 같은 토큰 만료", func(t *testing.T) {
		_, _, d, tok, _ := newSessionRig(t)
		if c, _, err := d.CallTool("file_read", read, tok); err != nil || c != domain.ExitSuccess {
			t.Fatalf("1차 = %d, %v", c, err)
		}
		if err := d.AdvanceClock(6 * time.Minute); err != nil {
			t.Fatal(err)
		}
		if c, _, err := d.CallTool("file_read", read, tok); err != nil || c != domain.ExitTokenInvalid {
			t.Fatalf("2차 = %d, %v (want 11)", c, err)
		}
	})

	t.Run("TC-020-02 Grant 회수 후 같은 토큰 거부", func(t *testing.T) {
		_, _, d, tok, g := newSessionRig(t)
		if c, _, err := d.CallTool("file_read", read, tok); err != nil || c != domain.ExitSuccess {
			t.Fatalf("1차 = %d, %v", c, err)
		}
		if err := d.RevokeGrant(context.Background(), g.ID); err != nil {
			t.Fatal(err)
		}
		if c, _, err := d.CallTool("file_read", read, tok); err != nil || c != domain.ExitAuthzDenied {
			t.Fatalf("2차 = %d, %v (want 12)", c, err)
		}
	})

	t.Run("TC-020-03 오프셋 스택 발급 iat 전진", func(t *testing.T) {
		env, _, d, _, _ := newSessionRig(t)
		base := env.MockClock.Now()
		if err := d.AdvanceClock(6 * time.Minute); err != nil {
			t.Fatal(err)
		}
		st, err := d.Stack()
		if err != nil {
			t.Fatal(err)
		}
		res, err := issueBudgetRoot(st, "sess-sub", "file:read:s.txt", time.Minute, domain.Budget{MaxCalls: 1})
		if err != nil {
			t.Fatal(err)
		}
		want := base.Add(6 * time.Minute).Unix()
		if got := res.Claims.IssuedAt; got < want || got > want+2 {
			t.Fatalf("iat = %d, want ≈ %d", got, want)
		}
	})

	t.Run("TC-020-04 음수 전진 거부, offset 불변", func(t *testing.T) {
		_, _, d, _, _ := newSessionRig(t)
		if err := d.AdvanceClock(-time.Minute); err == nil {
			t.Fatal("negative advance must fail")
		}
		if d.Offset() != 0 {
			t.Fatalf("offset = %v", d.Offset())
		}
	})

	t.Run("TC-020-05 Close 후 서버 고루틴 종료", func(t *testing.T) {
		_, _, d, tok, _ := newSessionRig(t)
		_, _, _ = d.CallTool("file_read", read, tok)
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-d.done:
		default:
			t.Fatal("server goroutine still running")
		}
	})
}
