package app_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/app"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

// 공개키가 하나도 없는 검증 전용 스택은 조립되지만, 키를 만들지 않고 모든 토큰을 거부한다.
func TestBuildStack_VerifyOnlyWithNoKeys_RejectsTokens(t *testing.T) {
	root := t.TempDir()
	pubPath := filepath.Join(root, "jwks.pub.json")
	const emptyJWKS = `{"version":1,"keys":[]}`
	if err := os.WriteFile(pubPath, []byte(emptyJWKS), 0644); err != nil {
		t.Fatal(err)
	}

	stack, err := app.BuildStack(app.AppConfig{
		StatePath:    filepath.Join(root, "state.json"),
		PubJWKSPath:  pubPath,
		ReplayPath:   filepath.Join(root, "replay.json"),
		AuditPath:    filepath.Join(root, "audit.jsonl"),
		WorkspaceDir: filepath.Join(root, "workspace"),
		VerifyOnly:   true,
	})
	if err != nil {
		t.Fatalf("BuildStack: %v", err)
	}
	defer func() {
		if cerr := stack.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	}()

	enc := base64.RawURLEncoding
	tok := enc.EncodeToString([]byte(`{"typ":"at+jwt","alg":"EdDSA","kid":"unknown-kid"}`)) + "." +
		enc.EncodeToString([]byte(`{"sub":"worker-01"}`)) + "." +
		enc.EncodeToString(make([]byte, 64))

	_, verr := stack.TokenVerifier.VerifyToken(tok, token.VerifyOptions{}, domain.AuditContext{TraceID: "t-nokeys"})
	if got := domain.ReasonFromError(verr, ""); got != domain.ReasonTokenKeyNotFound {
		t.Fatalf("reason = %q, want %q (err=%v)", got, domain.ReasonTokenKeyNotFound, verr)
	}

	after, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != emptyJWKS {
		t.Fatalf("verify-only stack modified public key file: %s", after)
	}
}
