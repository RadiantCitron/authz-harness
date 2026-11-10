package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/authz/state"
	"authz-harness/internal/cli"
	"authz-harness/internal/domain"
)

func setupApprovalRunner(t *testing.T) (*cli.ApprovalRunner, *bytes.Buffer, *bytes.Buffer, string, string) {
	t.Helper()
	dir := t.TempDir()
	sp, ap := filepath.Join(dir, "grants_state.json"), filepath.Join(dir, "audit.jsonl")
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	r, err := cli.NewApprovalRunner(out, errOut, sp, ap)
	if err != nil {
		t.Fatal(err)
	}
	return r, out, errOut, sp, ap
}

func TestApprovalGrantAndList(t *testing.T) { // TC-020-04
	r, out, errOut, sp, ap := setupApprovalRunner(t)
	ctx := context.Background()
	seedApprovalGrantFile(t, sp, "worker-01", domain.ActionFileWrite, "secret.txt")
	code := r.Run(ctx, []string{"grant", "--subject", "worker-01", "--action", "file:write", "--resource", "secret.txt", "--jti", "jti-01", "--ttl", "5m"})
	if code != domain.ExitSuccess {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	st, _ := os.ReadFile(sp)
	if !strings.Contains(string(st), `"token_jti": "jti-01"`) && !strings.Contains(string(st), `"token_jti":"jti-01"`) {
		t.Fatalf("ledger missing approval: %s", st)
	}
	au, _ := os.ReadFile(ap)
	if !strings.Contains(string(au), "approval.granted") {
		t.Fatal("audit missing")
	}
	out.Reset()
	if code := r.Run(ctx, []string{"list", "--subject", "worker-01"}); code != domain.ExitSuccess || !strings.Contains(out.String(), "jti-01") {
		t.Fatalf("list: %d %s", code, out.String())
	}
}

func TestApprovalGrantBadInput(t *testing.T) { // TC-020-05
	r, _, _, sp, _ := setupApprovalRunner(t)
	base := []string{"grant", "--subject", "w", "--action", "file:write", "--resource", "s.txt", "--jti", "j"}
	for _, extra := range [][]string{{"--arg-hash", "sha256:XYZ"}, {"--ttl", "2h"}} {
		if code := r.Run(context.Background(), append(append([]string{}, base...), extra...)); code != domain.ExitBadInput {
			t.Errorf("%v: exit %d", extra, code)
		}
	}
	if b, err := os.ReadFile(sp); err == nil && strings.Contains(string(b), "token_jti") {
		t.Fatal("ledger must be unchanged")
	}
}

func TestGrantCreateRequiresApprovalFlag(t *testing.T) {
	runner, _, errOut := setupTestGrantRunner(t)
	code := runner.Run(context.Background(), []string{"create", "--sub", "w", "--action", "file:write", "--resource", "s.txt", "--requires-approval"})
	if code != domain.ExitSuccess {
		t.Fatalf("exit %d %s", code, errOut.String())
	}
}

// seedApprovalGrantFile 은 상태 파일에 사람 승인이 필요한 활성 Grant 를 감사 없이 넣는다 (ADR 0011 D-4 준비용).
func seedApprovalGrantFile(t *testing.T, statePath, sub string, act domain.Action, res string) {
	t.Helper()
	st, err := state.NewFileStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *state.GrantsState) error {
		s.Grants = append(s.Grants, domain.Grant{
			ID: "seed-" + sub, Subject: sub, Action: act, Resource: res,
			Status: domain.GrantStatusActive, CreatedAt: time.Now().UTC(), RequiresApproval: true,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// 계획 052 M11: 허가 없이 approval grant 를 실행하면 종료 코드 12, 원장은 바뀌지 않는다.
func TestApprovalGrant_NoGrant_Exit12(t *testing.T) {
	r, _, _, sp, _ := setupApprovalRunner(t)
	code := r.Run(context.Background(), []string{"grant", "--subject", "worker-01", "--action", "file:write", "--resource", "secret.txt", "--jti", "jti-01"})
	if code != domain.ExitAuthzDenied {
		t.Fatalf("exit %d, want %d", code, domain.ExitAuthzDenied)
	}
	if b, err := os.ReadFile(sp); err == nil && strings.Contains(string(b), "token_jti") {
		t.Fatalf("ledger must be unchanged: %s", b)
	}
}
