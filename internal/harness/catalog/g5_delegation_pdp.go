package catalog

import (
	"context"
	"fmt"
	"time"

	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G5: RFC 8693 위임 및 PDP 인가 정책 (E2E-19 ~ E2E-24)
func g5Scenarios() []harness.Scenario {
	return []harness.Scenario{
		&e2e19Scenario{},
		&e2e20Scenario{},
		&e2e21Scenario{},
		&e2e22Scenario{},
		&e2e23Scenario{},
		&e2e24Scenario{},
	}
}

// E2E-19: 팀장 Scope 초과 위임 시도 거부
type e2e19Scenario struct {
	parentToken string
}

func (s *e2e19Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-19",
		Group:              "G5",
		Name:               "팀장 Scope 초과 위임 시도 거부",
		Description:        "부모 토큰이 보유하지 않은 권한(file:write)을 자식 토큰에게 축소 위임하려는 시도는 RFC 8693 위임 관문에서 차단된다.",
		AttackClass:        "DelegationScopeExceeded",
		ParadoxExplanation: "부모 토큰이 보유하지 않은 상위 권한을 자식에게 축소 위임하려는 월권을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "token.exchange.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonDelegationScopeExceeded,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e19Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	// 부모 토큰: file:read 만 보유
	tok, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01", "lead-01", "file:read", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.parentToken = tok
	return nil
}

func (s *e2e19Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	exchSvc := exchange.NewExchangeService(
		stack.TokenIssuer,
		stack.TokenVerifier,
		stack.ClientReg,
		exchange.NewDownscopeValidator(),
		stack.AuditWriter,
		env.MockClock,
	)

	// 부모 토큰(read)으로 자식에게 file:write 위임 시도
	req := exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  s.parentToken,
		ChildSubject: "worker-01",
		Scope:        "file:write", // 초과
		Audience:     "authz-harness",
		TTL:          5 * time.Minute,
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-19",
		Actor:   "client-subagent",
		Reason:  "token.exchange",
	}

	_, err = exchSvc.Exchange(ctx, req, auditCtx)
	if err != nil {
		return domain.ExitAuthzDenied, nil
	}
	return domain.ExitSuccess, nil
}

// E2E-20: 팀장 수명(TTL) 초과 위임 시도 거부
type e2e20Scenario struct {
	parentToken string
}

func (s *e2e20Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-20",
		Group:              "G5",
		Name:               "팀장 수명(TTL) 초과 위임 시도 거부",
		Description:        "부모 토큰의 잔여 만료 시간을 초과하는 장기 유효 자식 토큰 발급 시도는 RFC 8693 관문에서 차단된다.",
		AttackClass:        "DelegationTTLExceeded",
		ParadoxExplanation: "부모 토큰의 잔여 만료 시간을 초과하는 장기 유효 자식 토큰 발급을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "token.exchange.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonDelegationTTLExceeded,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e20Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	// 부모 토큰: TTL 5분
	tok, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01", "lead-01", "file:read", 5*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.parentToken = tok
	return nil
}

func (s *e2e20Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	exchSvc := exchange.NewExchangeService(
		stack.TokenIssuer,
		stack.TokenVerifier,
		stack.ClientReg,
		exchange.NewDownscopeValidator(),
		stack.AuditWriter,
		env.MockClock,
	)

	// 부모 토큰(5분 잔여)으로 자식에게 10분 TTL 위임 시도
	req := exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  s.parentToken,
		ChildSubject: "worker-01",
		Scope:        "file:read",
		Audience:     "authz-harness",
		TTL:          10 * time.Minute, // 초과
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-20",
		Actor:   "client-subagent",
		Reason:  "token.exchange",
	}

	_, err = exchSvc.Exchange(ctx, req, auditCtx)
	if err != nil {
		return domain.ExitAuthzDenied, nil
	}
	return domain.ExitSuccess, nil
}

// E2E-21: 최대 위임 깊이(depth) 초과 거부
type e2e21Scenario struct {
	deepToken string
}

func (s *e2e21Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-21",
		Group:              "G5",
		Name:               "최대 위임 깊이(depth) 초과 거부",
		Description:        "허용된 최대 위임 사슬 깊이(MaxDepth=3)를 초과하는 다단계 위임 시도는 차단된다.",
		AttackClass:        "DelegationDepthExceeded",
		ParadoxExplanation: "허용된 최대 체인 깊이(예: depth 3)를 초과하는 다단계 위임을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "token.exchange.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonDelegationDepthExceeded,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e21Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 깊이 3을 가진 부모 토큰 발행 (이미 최대치 도달)
	req := token.IssueRequest{
		ClientID:        "client-orchestrator",
		ClientSecret:    "orchestrator-secret-key-01",
		Subject:         "lead-deep",
		Scope:           "file:read",
		Audience:        "authz-harness",
		TTL:             10 * time.Minute,
		DelegationDepth: 3,
		Actor: &domain.ActorClaim{
			Subject: "lead-deep-prev",
		},
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-21-setup",
		Actor:   "setup",
		Reason:  "token.issue",
	}
	res, err := stack.TokenIssuer.IssueToken(req, token.IssueOptions{}, auditCtx)
	if err != nil {
		return err
	}
	s.deepToken = res.TokenString
	return nil
}

func (s *e2e21Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	exchSvc := exchange.NewExchangeService(
		stack.TokenIssuer,
		stack.TokenVerifier,
		stack.ClientReg,
		exchange.NewDownscopeValidator(),
		stack.AuditWriter,
		env.MockClock,
	)

	req := exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  s.deepToken,
		ChildSubject: "worker-01",
		Scope:        "file:read",
		Audience:     "authz-harness",
		TTL:          5 * time.Minute,
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-21",
		Actor:   "client-subagent",
		Reason:  "token.exchange",
	}

	_, err = exchSvc.Exchange(ctx, req, auditCtx)
	if err != nil {
		return domain.ExitAuthzDenied, nil
	}
	return domain.ExitSuccess, nil
}

// E2E-22: Read 전용 자식 토큰으로 Write 시도 거부
type e2e22Scenario struct {
	readOnlyChildToken string
}

func (s *e2e22Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-22",
		Group:              "G5",
		Name:               "Read 전용 자식 토큰으로 Write 시도 거부",
		Description:        "읽기 전용(file:read)으로 축소 위임된 자식 토큰으로 쓰기(write)를 시도할 경우 PDP에서 스코프 불충분으로 차단된다.",
		AttackClass:        "InsufficientScopeWrite",
		ParadoxExplanation: "읽기 전용으로 축소 위임된 자식 토큰으로 쓰기를 시도한 공격을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "readonly.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonTokenInsufficientScope,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e22Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. Grant 등록 (worker-01 에 대해 file:write 권한은 존재하지 않음 또는 파일 권한 존재해도 토큰 스코프가 read 전용)
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, "readonly.txt"); err != nil {
		return err
	}

	// 2. file:read 전용 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.readOnlyChildToken = tok
	return nil
}

func (s *e2e22Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// file:write 액션 시도 -> 스코프 불충분 거부
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.readOnlyChildToken,
		Action:   domain.ActionFileWrite,
		Resource: "readonly.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-22",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-23: 미허가 리소스 경로 접근 거부
type e2e23Scenario struct {
	token string
}

func (s *e2e23Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-23",
		Group:              "G5",
		Name:               "미허가 리소스 경로 접근 거부",
		Description:        "활성 권한(Grant)이 등록되지 않은 비인가 파일 리소스에 대한 접근 요청은 PDP에서 차단된다.",
		AttackClass:        "NoActiveGrant",
		ParadoxExplanation: "활성 권한(Grant)이 없는 비인가 리소스 경로에 대한 접근을 거부했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "unauthorized.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonNoActiveGrant,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e23Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	// 토큰은 발급하되 unauthorized.txt 에 대한 Grant 는 등록하지 않음
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e23Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "unauthorized.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-23",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-24: Subject Epoch 증가를 통한 일괄 철회
type e2e24Scenario struct {
	token string
}

func (s *e2e24Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-24",
		Group:              "G5",
		Name:               "Subject Epoch 증가를 통한 일괄 철회",
		Description:        "주체의 Security Epoch가 1 증가하면 이전 Epoch(1)로 발급된 미만료 토큰의 접근이 PDP에서 즉각 차단된다.",
		AttackClass:        "EpochRevocation",
		ParadoxExplanation: "주체의 Security Epoch를 올려 탈취 의심 구형 토큰을 일괄 무력화했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "epoch_test.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonSubjectEpochRevoked,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e24Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. Grant 등록
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "epoch_test.txt"); err != nil {
		return err
	}

	// 2. Epoch=1 상태에서 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok

	// 3. 주체의 Epoch 를 2로 증가 (일괄 무효화)
	if _, err := stack.PAP.BumpEpoch(ctx, "worker-01"); err != nil {
		return fmt.Errorf("bump epoch: %w", err)
	}

	return nil
}

func (s *e2e24Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "epoch_test.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-24",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}
