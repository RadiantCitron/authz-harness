package catalog

import (
	"context"
	"fmt"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G4: 클레임 바인딩, 시간 유효성 및 Replay 공격 방어 (E2E-14 ~ E2E-18)
func g4Scenarios() []harness.Scenario {
	return withStages([]harness.Scenario{
		&e2e14Scenario{},
		&e2e15Scenario{},
		&e2e16Scenario{},
		&e2e17Scenario{},
		&e2e18Scenario{},
	})
}

// E2E-14: 만료된 토큰 즉시 거부
type e2e14Scenario struct {
	token string
}

func (s *e2e14Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-14",
		Group:              "G4",
		Name:               "만료된 토큰 즉시 거부",
		Description:        "유효기간(exp)이 경과한 토큰으로 접근 시 가상 시계 기반 0.001초 지연 없이 즉각 차단된다.",
		AttackClass:        "ExpiredToken",
		ParadoxExplanation: "exp 시각이 경과한 토큰의 접근을 0.001초 지연 없이 즉각 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonTokenExpired,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e14Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	// 유효기간 1초 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 1*time.Second, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e14Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// 가상 시계 10초 미래 오프셋 적용 -> 만료 상태 시뮬레이션 (Zero-Sleep)
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:       s.token,
		Action:      domain.ActionFileWrite,
		Resource:    "output.txt",
		Data:        []byte("fail"),
		ClockOffset: 10 * time.Second,
		TraceID:     "trace-e2e-14",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-15: 미래 발급/활성(nbf) 토큰 거부
type e2e15Scenario struct {
	token string
}

func (s *e2e15Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-15",
		Group:              "G4",
		Name:               "미래 발급/활성(nbf) 토큰 거부",
		Description:        "현재 시각보다 미래의 nbf를 가진 토큰으로 접근 시 사전 차단된다.",
		AttackClass:        "FutureNbfToken",
		ParadoxExplanation: "현재 시각보다 미래의 nbf를 가진 미도래 토큰의 접근을 사전 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonTokenNotYetValid,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e15Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e15Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// 가상 시계 10분 과거 오프셋 적용 -> nbf 이전 시각 시뮬레이션
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:       s.token,
		Action:      domain.ActionFileWrite,
		Resource:    "output.txt",
		Data:        []byte("fail"),
		ClockOffset: -10 * time.Minute,
		// nbf 이전 시각을 일부러 시뮬레이션하는 유일한 시나리오이므로 음수 오프셋을 명시 허용한다 (계획 040).
		AllowNegativeClockOffset: true,
		TraceID:                  "trace-e2e-15",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-16: iss/aud 불일치 토큰 거부
type e2e16Scenario struct {
	token string
}

func (s *e2e16Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-16",
		Group:              "G4",
		Name:               "iss/aud 불일치 토큰 거부",
		Description:        "발급자(iss) 또는 수신자(aud)가 일치하지 않는 토큰은 대상 서비스 바인딩 불일치로 차단된다.",
		AttackClass:        "AudienceMismatch",
		ParadoxExplanation: "발급자(iss) 또는 수신자(aud)가 일치하지 않는 이종 시스템 토큰을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonTokenInvalidIssAud,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e16Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	// Audience 를 다른 시스템으로 발급
	req := token.IssueRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		Subject:      "worker-01",
		Scope:        "file:write",
		Audience:     "foreign-authz-system",
		TTL:          10 * time.Minute,
		Epoch:        1,
	}
	auditCtx := domain.AuditContext{
		TraceID: "trace-e2e-16",
		Actor:   "setup",
		Reason:  "token.issue",
	}
	res, err := stack.TokenIssuer.IssueToken(req, token.IssueOptions{}, auditCtx)
	if err != nil {
		return err
	}
	s.token = res.TokenString
	return nil
}

func (s *e2e16Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:            s.token,
		Action:           domain.ActionFileWrite,
		Resource:         "output.txt",
		Data:             []byte("fail"),
		ExpectedAudience: "authz-harness",
		TraceID:          "trace-e2e-16",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-17: 타 주체 토큰 도용(sub 불일치) 거부
type e2e17Scenario struct {
	token string
}

func (s *e2e17Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-17",
		Group:              "G4",
		Name:               "타 주체 토큰 도용(sub 불일치) 거부",
		Description:        "다른 주체(Subject) 명의로 발급된 토큰을 도용하여 접근 시 신원 불일치로 차단된다.",
		AttackClass:        "SubjectImpersonation",
		ParadoxExplanation: "다른 워커(Subject) 명의로 발급된 토큰을 도용한 신원 위장을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonTokenSubjectMismatch,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e17Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	// worker-01 명의로 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e17Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// worker-02 주체 기대치와 불일치
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:           s.token,
		Action:          domain.ActionFileWrite,
		Resource:        "output.txt",
		Data:            []byte("fail"),
		ExpectedSubject: "worker-02",
		TraceID:         "trace-e2e-17",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-18: 일회성 토큰 재사용(jti Replay) 거부
type e2e18Scenario struct {
	token string
}

func (s *e2e18Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-18",
		Group:              "G4",
		Name:               "일회성 토큰 재사용(jti Replay) 거부",
		Description:        "원장에 이미 등록된 jti 토큰을 2회차 재사용할 경우 Replay 공격으로 적발되어 거부된다.",
		AttackClass:        "ReplayAttack",
		ParadoxExplanation: "이미 사용된 jti를 재전송한 재생 공격(Replay Attack)을 원장에서 적발했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:         "replay_file.txt",
				ExpectExist:     true,
				ExpectedContent: "first write ok", // 1차 쓰기만 성공, 2차 공격은 차단되어 덮어쓰기 무변화
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonTokenReplayDetected,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e18Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// Grant 등록
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "replay_file.txt"); err != nil {
		return err
	}

	// 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok

	// 1회차 정상 사용 -> jti 원장에 소비 등록됨
	res1, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "replay_file.txt",
		Data:     []byte("first write ok"),
		TraceID:  "trace-e2e-18-first",
	})
	if err != nil || res1.ExitCode != domain.ExitSuccess {
		return fmt.Errorf("setup first execution failed: res=%+v err=%w", res1, err)
	}

	return nil
}

func (s *e2e18Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// 2회차 재사용 시도 -> Replay 거부되어야 함
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "replay_file.txt",
		Data:     []byte("replayed malicious data"),
		TraceID:  "trace-e2e-18-second",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}
