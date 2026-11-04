package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/audit"
	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/exchange"
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
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

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

// harnessStack 은 단일 시나리오가 샌드박스 내에서 상호작용하는 모든 컴포넌트 묶음이다.
type harnessStack struct {
	Env             *harness.SandboxEnvironment
	AuditWriter     audit.Writer
	KeyStore        keys.Store
	KeyManager      keys.KeyManager
	TokenIssuer     token.TokenIssuer
	TokenVerifier   token.TokenVerifier
	ClientReg       *token.InMemoryClientRegistry
	ReplayLedger    token.ReplayLedger
	BudgetLedger    budget.Ledger
	ExchangeService exchange.Service
	StateStore      state.Store
	PAP             pap.Service
	PIP             pip.Service
	PDP             pdp.Service
	Jail            jail.Jail
	PEP             pep.Gateway
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
	return setupHarnessStackWithClock(env, env.MockClock)
}

// setupHarnessStackWithClock 은 같은 샌드박스 경로에 주어진 시계로 스택을 조립한다 (세션 시간 전진용).
func setupHarnessStackWithClock(env *harness.SandboxEnvironment, clock domain.Clock) (*harnessStack, error) {
	st, err := app.BuildStack(app.AppConfig{
		StatePath:    env.StatePath,
		PrivKeyPath:  env.PrivKeyPath,
		PubJWKSPath:  env.PubJWKSPath,
		ReplayPath:   env.ReplayPath,
		AuditPath:    env.AuditPath,
		WorkspaceDir: env.WorkspaceDir,
		Clock:        clock,
	})
	if err != nil {
		return nil, fmt.Errorf("setup stack via app builder: %w", err)
	}

	return &harnessStack{
		Env:             env,
		AuditWriter:     st.AuditWriter,
		KeyStore:        st.KeyStore,
		KeyManager:      st.KeyManager,
		TokenIssuer:     st.TokenIssuer,
		TokenVerifier:   st.TokenVerifier,
		ClientReg:       st.ClientReg,
		ReplayLedger:    st.ReplayLedger,
		BudgetLedger:    st.BudgetLedger,
		ExchangeService: st.ExchangeService,
		StateStore:      st.StateStore,
		PAP:             st.PAP,
		PIP:             st.PIP,
		PDP:             st.PDP,
		Jail:            st.Jail,
		PEP:             st.PEP,
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

// ActionRequest 는 카탈로그 시나리오가 하네스 환경에서 액션을 실행할 때 전달하는 표준 요청 구조체다.
type ActionRequest struct {
	Token                string
	Action               domain.Action
	Resource             string
	Data                 []byte
	TraceID              string
	CallerID             string
	InjectAuditFailure   bool
	InjectRevokeBeforeIO bool
	ClockOffset          time.Duration // 0 이상만 허용(서브프로세스 경로·브리지는 음수를 ExitBadInput 으로 거부)
}

// executeHarnessAction 은 env.BinaryPath 유무에 따라 서브프로세스 또는 인메모리 PEP로 액션을 라우팅하여 실행하고 종료 코드를 반환한다.
func executeHarnessAction(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, req ActionRequest) (domain.ExitCode, error) {
	// 1. BinaryPath 가 주입된 경우 실제 OS 서브프로세스(authz-harness subagent worker) 스폰 실행
	if env != nil && env.BinaryPath != "" && !req.InjectAuditFailure {
		spawner, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
			BinaryPath: env.BinaryPath,
			Args: []string{
				"subagent", "worker",
				"-workspace", env.WorkspaceDir,
				"-state-file", env.StatePath,
				"-pub-jwks-file", env.PubJWKSPath,
				"-replay-file", env.ReplayPath,
				"-audit-file", env.AuditPath,
			},
			Audit: stack.AuditWriter,
		})
		if err != nil {
			return domain.ExitInternalError, fmt.Errorf("create subprocess spawner: %w", err)
		}

		res, err := spawner.Spawn(ctx, subagent.SubagentRequest{
			TraceID:              req.TraceID,
			Token:                req.Token,
			Action:               string(req.Action),
			FilePath:             req.Resource,
			Data:                 string(req.Data),
			InjectRevokeBeforeIO: req.InjectRevokeBeforeIO,
			ClockOffsetSeconds:   int64(req.ClockOffset / time.Second),
		})
		if err != nil {
			// 감사 실패 등 도메인 에러 판정
			var dErr *domain.Error
			if errors.As(err, &dErr) {
				return dErr.ExitCode, err
			}
			return domain.ExitInternalError, err
		}
		return domain.ExitCode(res.ExitCode), nil
	}

	// 2. InProc 모드 (또는 인메모리 에러 주입 테스트)
	pepReq := pep.Request{
		Token:                req.Token,
		Action:               req.Action,
		Resource:             req.Resource,
		Data:                 req.Data,
		TraceID:              req.TraceID,
		InjectAuditFailure:   req.InjectAuditFailure,
		InjectRevokeBeforeIO: req.InjectRevokeBeforeIO,
		ClockOffset:          req.ClockOffset,
	}

	res, err := stack.PEP.Execute(ctx, pepReq)
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}
