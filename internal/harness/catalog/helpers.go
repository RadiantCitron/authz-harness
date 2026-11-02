package catalog

import (
	"context"
	"fmt"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/jail"
)

// harnessStack 은 단일 시나리오가 샌드박스 내에서 상호작용하는 모든 컴포넌트 묶음이다.
type harnessStack struct {
	Env           *harness.SandboxEnvironment
	AuditWriter   audit.Writer
	KeyStore      keys.Store
	KeyManager    keys.KeyManager
	TokenIssuer   token.TokenIssuer
	TokenVerifier token.TokenVerifier
	ClientReg     *token.InMemoryClientRegistry
	ReplayLedger  token.ReplayLedger
	StateStore    state.Store
	PAP           pap.Service
	PIP           pip.Service
	PDP           pdp.Service
	Jail          jail.Jail
	PEP           pep.Gateway
}

// Close 는 스택에 바인딩된 리소스(감사 로그 기록기 등)를 안전하게 닫아 파일 디스크립터 누수를 방지한다.
func (s *harnessStack) Close() error {
	if s.AuditWriter != nil {
		return s.AuditWriter.Close()
	}
	return nil
}

// setupHarnessStack 은 주어진 SandboxEnvironment 경로를 바탕으로 전체 스택을 초기화한다.
func setupHarnessStack(env *harness.SandboxEnvironment) (*harnessStack, error) {
	st, err := app.BuildStack(app.AppConfig{
		StatePath:    env.StatePath,
		PrivKeyPath:  env.PrivKeyPath,
		PubJWKSPath:  env.PubJWKSPath,
		ReplayPath:   env.ReplayPath,
		AuditPath:    env.AuditPath,
		WorkspaceDir: env.WorkspaceDir,
		Clock:        env.MockClock,
	})
	if err != nil {
		return nil, fmt.Errorf("setup stack via app builder: %w", err)
	}

	return &harnessStack{
		Env:           env,
		AuditWriter:   st.AuditWriter,
		KeyStore:      st.KeyStore,
		KeyManager:    st.KeyManager,
		TokenIssuer:   st.TokenIssuer,
		TokenVerifier: st.TokenVerifier,
		ClientReg:     st.ClientReg,
		ReplayLedger:  st.ReplayLedger,
		StateStore:    st.StateStore,
		PAP:           st.PAP,
		PIP:           st.PIP,
		PDP:           st.PDP,
		Jail:          st.Jail,
		PEP:           st.PEP,
	}, nil
}

// issueTestToken 은 표준 테스트용 토큰을 발행하는 헬퍼 함수다.
func issueTestToken(
	stack *harnessStack,
	clientID, clientSecret, subject, scope string,
	ttl time.Duration,
	opts token.IssueOptions,
) (string, error) {
	req := token.IssueRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Subject:      subject,
		Scope:        scope,
		Audience:     "authz-harness",
		TTL:          ttl,
		Epoch:        1,
	}
	auditCtx := domain.AuditContext{
		TraceID: "test-trace-setup",
		Actor:   "setup",
		Reason:  "token.issue",
	}
	res, err := stack.TokenIssuer.IssueToken(req, opts, auditCtx)
	if err != nil {
		return "", err
	}
	return res.TokenString, nil
}

// grantPermission 은 PAP에 주체의 권한을 등록하는 헬퍼 함수다.
func grantPermission(
	ctx context.Context,
	stack *harnessStack,
	subject string,
	action domain.Action,
	resource string,
) (*domain.Grant, error) {
	return stack.PAP.CreateGrant(ctx, pap.CreateGrantRequest{
		Subject:  subject,
		Action:   action,
		Resource: resource,
	})
}
