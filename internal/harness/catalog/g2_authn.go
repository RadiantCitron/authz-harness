package catalog

import (
	"context"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G2: 워크로드 인증 (AuthN) 거부 (E2E-04 ~ E2E-06)
func g2Scenarios() []harness.Scenario {
	return []harness.Scenario{
		&e2e04Scenario{},
		&e2e05Scenario{},
		&e2e06Scenario{},
	}
}

// E2E-04: 미등록 클라이언트 토큰 요청 거부
type e2e04Scenario struct{}

func (s *e2e04Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-04",
		Group:              "G2",
		Name:               "미등록 클라이언트 토큰 요청 거부",
		Description:        "등록되지 않은 미승인 클라이언트 ID로 토큰 발급을 요청할 경우 인증 관문에서 즉각 거부된다.",
		AttackClass:        "UnknownClientAuthN",
		ParadoxExplanation: "등록되지 않은 클라이언트 ID 요청을 인증 관문에서 즉각 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "dummy.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "token.issue.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonAuthnUnknownClient,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e04Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *e2e04Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	req := token.IssueRequest{
		ClientID:     "unknown-attacker-client",
		ClientSecret: "any-secret",
		Subject:      "worker-01",
		Scope:        "file:read",
		Audience:     "authz-harness",
		TTL:          10 * time.Minute,
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-04",
		Actor:   "unknown-attacker-client",
		Reason:  "token.issue",
	}

	_, err = stack.TokenIssuer.IssueToken(req, token.IssueOptions{}, auditCtx)
	if err != nil {
		// 인증 실패 시 ExitTokenInvalid (11)
		return domain.ExitTokenInvalid, nil
	}
	return domain.ExitSuccess, nil
}

// E2E-05: 잘못된 클라이언트 시크릿 거부
type e2e05Scenario struct{}

func (s *e2e05Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-05",
		Group:              "G2",
		Name:               "잘못된 클라이언트 시크릿 거부",
		Description:        "등록된 클라이언트 ID이나 비밀키(Secret)가 틀린 경우 정시성 비교를 통해 인증 관문에서 차단된다.",
		AttackClass:        "InvalidSecretAuthN",
		ParadoxExplanation: "비밀키(Secret)가 일치하지 않는 위조 요청을 인증 관문에서 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "dummy.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "token.issue.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonAuthnInvalidSecret,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e05Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *e2e05Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	req := token.IssueRequest{
		ClientID:     "client-subagent",
		ClientSecret: "wrong-password-attacker",
		Subject:      "worker-01",
		Scope:        "file:read",
		Audience:     "authz-harness",
		TTL:          10 * time.Minute,
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-05",
		Actor:   "client-subagent",
		Reason:  "token.issue",
	}

	_, err = stack.TokenIssuer.IssueToken(req, token.IssueOptions{}, auditCtx)
	if err != nil {
		return domain.ExitTokenInvalid, nil
	}
	return domain.ExitSuccess, nil
}

// E2E-06: 정지된(Suspended) 클라이언트 거부
type e2e06Scenario struct{}

func (s *e2e06Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-06",
		Group:              "G2",
		Name:               "정지된(Suspended) 클라이언트 거부",
		Description:        "관리자에 의해 비활성화(Active=false) 처리된 정지 클라이언트의 토큰 발급 요청을 차단한다.",
		AttackClass:        "SuspendedClientAuthN",
		ParadoxExplanation: "비활성화/정지 처리된 클라이언트의 신규 토큰 발급 요청을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "dummy.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "token.issue.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonAuthnClientSuspended,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e06Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *e2e06Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// 정지된 클라이언트 등록
	stack.ClientReg.RegisterClient("client-suspended", "secret-key", "Suspended Client", []string{"*"}, false)

	req := token.IssueRequest{
		ClientID:     "client-suspended",
		ClientSecret: "secret-key",
		Subject:      "worker-01",
		Scope:        "file:read",
		Audience:     "authz-harness",
		TTL:          10 * time.Minute,
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-06",
		Actor:   "client-suspended",
		Reason:  "token.issue",
	}

	_, err = stack.TokenIssuer.IssueToken(req, token.IssueOptions{}, auditCtx)
	if err != nil {
		return domain.ExitTokenInvalid, nil
	}
	return domain.ExitSuccess, nil
}
