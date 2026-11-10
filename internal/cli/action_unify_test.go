package cli_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"authz-harness/internal/authz/state"
	"authz-harness/internal/cli"
	"authz-harness/internal/domain"
)

// 계획 020 V3·D-06: 모든 CLI 입구가 domain.ParseAction 과 같은 입력 집합(공백·대소문자·read/write 별칭)을 받는다.
func TestCLI_ActionParsingIsUnified(t *testing.T) {
	ctx := context.Background()

	t.Run("grant create 는 별칭을 받는다", func(t *testing.T) {
		r, _, errOut := setupTestGrantRunner(t)
		if code := r.Run(ctx, []string{"create", "--sub", "w", "--action", " READ ", "--resource", "a.txt"}); code != domain.ExitSuccess {
			t.Fatalf("exit %d: %s", code, errOut.String())
		}
	})
	t.Run("grant create 는 오타를 14 로 거부한다", func(t *testing.T) {
		r, _, _ := setupTestGrantRunner(t)
		if code := r.Run(ctx, []string{"create", "--sub", "w", "--action", "typo", "--resource", "a.txt"}); code != domain.ExitBadInput {
			t.Fatalf("exit %d, want %d", code, domain.ExitBadInput)
		}
	})
	t.Run("pdp decide 는 별칭을 받는다", func(t *testing.T) {
		sp, ap := setupPDPCliTest(t)
		var out, errOut bytes.Buffer
		r, err := cli.NewPDPRunner(&out, &errOut, sp, ap)
		if err != nil {
			t.Fatal(err)
		}
		// 별칭이 통하면 액션 검증을 넘어 판정(Grant 없음 → DENY 12)에 도달한다. 검증 단계 거부(14)가 아니어야 한다.
		if code := r.Run(ctx, []string{"decide", "--sub", "w", "--action", " Read ", "--resource", "a.txt"}); code != domain.ExitAuthzDenied {
			t.Fatalf("exit %d, want %d (stderr: %s)", code, domain.ExitAuthzDenied, errOut.String())
		}
	})
	t.Run("approval grant 는 오타 액션을 저장하지 않는다", func(t *testing.T) {
		r, _, _, sp, _ := setupApprovalRunner(t)
		code := r.Run(ctx, []string{"grant", "--subject", "w", "--action", "typo", "--resource", "s.txt", "--jti", "j"})
		if code != domain.ExitBadInput {
			t.Fatalf("exit %d, want %d", code, domain.ExitBadInput)
		}
		if b, err := os.ReadFile(sp); err == nil && strings.Contains(string(b), "typo") {
			t.Fatalf("ledger must not contain the typo action: %s", b)
		}
	})
	t.Run("approval grant 는 별칭을 정식 액션으로 저장한다", func(t *testing.T) {
		r, _, errOut, sp, _ := setupApprovalRunner(t)
		seedApprovalGrantFile(t, sp, "w", domain.ActionFileWrite, "s.txt")
		if code := r.Run(ctx, []string{"grant", "--subject", "w", "--action", " Write ", "--resource", "s.txt", "--jti", "j"}); code != domain.ExitSuccess {
			t.Fatalf("exit %d: %s", code, errOut.String())
		}
		st, err := state.NewFileStore(sp)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := st.Load()
		if err != nil || len(loaded.Approvals) != 1 || loaded.Approvals[0].Action != domain.ActionFileWrite {
			t.Fatalf("ledger must store canonical file:write approval: %v %+v", err, loaded)
		}
	})
}
