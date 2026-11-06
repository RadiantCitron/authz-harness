package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/domain"
)

type failingAuditWriter struct{}

func (failingAuditWriter) Log(audit.Event) error { return errors.New("injected") }
func (failingAuditWriter) Close() error          { return nil }

// errKeyManager 는 모든 변경이 일반 저장 오류로 실패하는 KeyManager 다.
type errKeyManager struct{ keys.KeyManager }

func (errKeyManager) RotateKey(domain.AuditContext) (*domain.JWK, error) {
	return nil, errors.New("disk full")
}
func (errKeyManager) RevokeKey(string, domain.AuditContext) error { return errors.New("disk full") }

func newKeysRunnerForFailure(t *testing.T) (*KeysRunner, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	priv := filepath.Join(dir, ".authz-state", "private", "signing_keys.priv.json")
	pub := filepath.Join(dir, ".authz-state", "public", "jwks.pub.json")
	var out, errOut bytes.Buffer
	r, err := NewKeysRunner(&out, &errOut, priv, pub, filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	active, err := r.mgr.GetActiveSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	store, err := keys.NewFileStore(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	failMgr, err := keys.NewManager(store, failingAuditWriter{})
	if err != nil {
		t.Fatal(err)
	}
	r.mgr = failMgr
	r.errOut = &errOut
	return r, &errOut, active.KID
}

// 계획 018 C1: 감사 실패는 종료 15 와 "audit logging failed" 로 알린다.
func TestKeysRunner_AuditFailureExitCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(kid string) []string
	}{
		{"rotate", func(string) []string { return []string{"rotate"} }},
		{"revoke", func(kid string) []string { return []string{"revoke", "--kid", kid} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, errOut, kid := newKeysRunnerForFailure(t)
			if code := r.Run(context.Background(), tc.args(kid)); code != domain.ExitAuditFailure {
				t.Fatalf("expected %d, got %d (stderr=%s)", domain.ExitAuditFailure, code, errOut.String())
			}
			if !strings.Contains(errOut.String(), "audit logging failed") {
				t.Fatalf("stderr must say audit logging failed, got %q", errOut.String())
			}
		})
	}
}

// 계획 018 C2: 없는 kid 폐기는 14 를 유지한다.
func TestKeysRunner_RevokeUnknownKidExitCode(t *testing.T) {
	r, _, _ := newKeysRunnerForFailure(t)
	if code := r.Run(context.Background(), []string{"revoke", "--kid", "no-such-kid"}); code != domain.ExitBadInput {
		t.Fatalf("expected %d, got %d", domain.ExitBadInput, code)
	}
}

// 계획 018 C3: 일반 저장 오류는 16 을 유지한다.
func TestKeysRunner_PlainStoreErrorExitCode(t *testing.T) {
	r, _, kid := newKeysRunnerForFailure(t)
	r.mgr = errKeyManager{r.mgr}
	if code := r.Run(context.Background(), []string{"rotate"}); code != domain.ExitInternalError {
		t.Fatalf("rotate: expected %d, got %d", domain.ExitInternalError, code)
	}
	if code := r.Run(context.Background(), []string{"revoke", "--kid", kid}); code != domain.ExitInternalError {
		t.Fatalf("revoke: expected %d, got %d", domain.ExitInternalError, code)
	}
}
