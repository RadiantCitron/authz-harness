package catalog

import (
	"context"
	"fmt"
	"time"

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
	Env          *harness.SandboxEnvironment
	AuditWriter  audit.Writer
	KeyStore     keys.Store
	KeyManager   keys.KeyManager
	TokenIssuer  token.TokenIssuer
	TokenVerifier token.TokenVerifier
	ClientReg    *token.InMemoryClientRegistry
	ReplayLedger token.ReplayLedger
	StateStore   state.Store
	PAP          pap.Service
	PIP          pip.Service
	PDP          pdp.Service
	Jail         jail.Jail
	PEP          pep.Gateway
}

// setupHarnessStack 은 주어진 SandboxEnvironment 경로를 바탕으로 전체 스택을 초기화한다.
func setupHarnessStack(env *harness.SandboxEnvironment) (*harnessStack, error) {
	auditWriter, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("setup stack: audit writer: %w", err)
	}

	keyStore, err := keys.NewFileStore(env.PrivKeyPath, env.PubJWKSPath)
	if err != nil {
		return nil, fmt.Errorf("setup stack: key store: %w", err)
	}

	keyMgr, err := keys.NewManager(keyStore, auditWriter, keys.WithClock(env.MockClock))
	if err != nil {
		return nil, fmt.Errorf("setup stack: key mgr: %w", err)
	}

	// 서명 키 초기 생성 (없을 경우)
	activeKey, err := keyMgr.GetActiveSigningKey()
	if err != nil || activeKey == nil {
		if _, err := keyMgr.RotateKey(domain.AuditContext{
			TraceID: "initial-key-rotation",
			Actor:   "system",
			Reason:  "initial active key setup",
		}); err != nil {
			return nil, fmt.Errorf("setup stack: initial rotate key: %w", err)
		}
	}

	clientReg := token.NewInMemoryClientRegistry()
	tokenIssuer := token.NewService(keyMgr, clientReg, auditWriter, env.MockClock)

	replayLedger, err := token.NewFileReplayLedger(env.ReplayPath, env.MockClock)
	if err != nil {
		return nil, fmt.Errorf("setup stack: replay ledger: %w", err)
	}

	tokenVerifier := token.NewVerifier(keyMgr, replayLedger, auditWriter, env.MockClock)

	stateStore, err := state.NewFileStore(env.StatePath)
	if err != nil {
		return nil, fmt.Errorf("setup stack: state store: %w", err)
	}

	papSvc := pap.NewService(stateStore, auditWriter, pap.WithClock(env.MockClock))
	pipSvc := pip.NewService(stateStore)
	pdpSvc := pdp.NewService(pipSvc, auditWriter)

	workspaceJail, err := jail.New(env.WorkspaceDir)
	if err != nil {
		return nil, fmt.Errorf("setup stack: jail: %w", err)
	}

	pepGateway, err := pep.NewGateway(pep.Config{
		Verifier:    tokenVerifier,
		PDP:         pdpSvc,
		Jail:        workspaceJail,
		AuditWriter: auditWriter,
		Clock:       env.MockClock,
	})
	if err != nil {
		return nil, fmt.Errorf("setup stack: pep gateway: %w", err)
	}

	return &harnessStack{
		Env:           env,
		AuditWriter:   auditWriter,
		KeyStore:      keyStore,
		KeyManager:    keyMgr,
		TokenIssuer:   tokenIssuer,
		TokenVerifier: tokenVerifier,
		ClientReg:     clientReg,
		ReplayLedger:  replayLedger,
		StateStore:    stateStore,
		PAP:           papSvc,
		PIP:           pipSvc,
		PDP:           pdpSvc,
		Jail:          workspaceJail,
		PEP:           pepGateway,
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
