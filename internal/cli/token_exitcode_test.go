package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

// 계획 017 S1 — CLI 종료 코드 시나리오 C1~C4 (계획 3.3에서 도출).

var issueArgs = []string{"issue", "--client-id", "client-orchestrator", "--client-secret", "orchestrator-secret-key-01",
	"--sub", "worker-01", "--scope", "file:read:docs/plan.txt", "--aud", "authz-service"}

func issueToken(t *testing.T, r *TokenRunner, out *bytes.Buffer) string {
	t.Helper()
	if c := r.Run(context.Background(), issueArgs); c != domain.ExitSuccess {
		t.Fatalf("issue: %d", c)
	}
	ls := strings.Split(strings.TrimSpace(out.String()), "\n")
	out.Reset()
	return ls[len(ls)-1]
}

// corruptedRunner 는 감사 꼬리를 손상시킨 뒤 새 러너를 만든다(쓰기가 실패하는 상태).
func corruptedRunner(t *testing.T, privPath, pubPath string) (*TokenRunner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := filepath.Dir(privPath)
	ap := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(ap, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"trace_id":"t","actor":"a","act`)
	f.Close()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	r, err := NewTokenRunner(out, errOut, filepath.Join(dir, "grants_state.json"), privPath, pubPath, filepath.Join(dir, "replay_ledger.json"), ap)
	if err != nil {
		t.Fatal(err)
	}
	return r, out, errOut
}

func TestExit_C1_IssueAuditCorrupted(t *testing.T) {
	_, _, _, priv, pub := setupCLITestRig(t)
	r2, _, errOut := corruptedRunner(t, priv, pub)
	if c := r2.Run(context.Background(), issueArgs); c != domain.ExitAuditFailure {
		t.Fatalf("want 15 got %d (%s)", c, errOut)
	}
}

func TestExit_C2_VerifyExchangeAuditCorrupted(t *testing.T) {
	r, out, _, priv, pub := setupCLITestRig(t)
	tok := issueToken(t, r, out)
	r2, _, errOut := corruptedRunner(t, priv, pub)
	if c := r2.Run(context.Background(), []string{"verify", "--token", tok, "--expected-aud", "authz-service"}); c != domain.ExitAuditFailure {
		t.Errorf("verify: want 15 got %d (%s)", c, errOut)
	}
	c := r2.Run(context.Background(), []string{"exchange", "--parent-token", tok, "--child-sub", "worker-01",
		"--scope", "file:read:docs/plan.txt", "--client-id", "client-orchestrator", "--client-secret", "orchestrator-secret-key-01"})
	if c != domain.ExitAuditFailure {
		t.Errorf("exchange: want 15 got %d (%s)", c, errOut)
	}
}

func TestExit_C3_SubjectNotAllowed(t *testing.T) {
	r, _, errOut, _, _ := setupCLITestRig(t)
	c := r.Run(context.Background(), []string{"issue", "--client-id", "client-subagent", "--client-secret", "subagent-secret-key-02",
		"--sub", "intruder", "--scope", "file:read:a"})
	if c != domain.ExitAuthzDenied {
		t.Fatalf("want 12 got %d (%s)", c, errOut)
	}
}

func TestExit_C4_WrongSecret(t *testing.T) {
	r, _, errOut, _, _ := setupCLITestRig(t)
	c := r.Run(context.Background(), []string{"issue", "--client-id", "client-orchestrator", "--client-secret", "wrong",
		"--sub", "worker-01", "--scope", "file:read:a"})
	if c != domain.ExitTokenInvalid {
		t.Fatalf("want 11 got %d (%s)", c, errOut)
	}
}
