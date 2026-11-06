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

// G3: 토큰 무결성 및 암호학적 서명 검증 (E2E-07 ~ E2E-13)
func g3Scenarios() []harness.Scenario {
	return withStages([]harness.Scenario{
		&e2e07Scenario{},
		&e2e08Scenario{},
		&e2e09Scenario{},
		&e2e10Scenario{},
		&e2e11Scenario{},
		&e2e12Scenario{},
		&e2e13Scenario{},
	})
}

// E2E-07: 토큰 누락 차단
type e2e07Scenario struct{}

func (s *e2e07Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-07",
		Group:              "G3",
		Name:               "토큰 누락 차단",
		Description:        "토큰 문자열이 공백이거나 누락된 상태로 파일 접근을 시도할 경우 Gate 1에서 즉각 차단된다.",
		AttackClass:        "MissingToken",
		ParadoxExplanation: "Authorization 헤더나 토큰 문자열이 누락된 요청을 1차 관문에서 차단했습니다.",
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
				ExpectedReason:   domain.ReasonTokenMalformed,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e07Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *e2e07Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    "", // 누락
		Action:   domain.ActionFileWrite,
		Resource: "output.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-07",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-08: 형식 파손(Malformed) 토큰 차단
type e2e08Scenario struct{}

func (s *e2e08Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-08",
		Group:              "G3",
		Name:               "형식 파손(Malformed) 토큰 차단",
		Description:        "점 분리 규격에 맞지 않는 파손된 JWT 토큰으로 접근 시도 시 차단된다.",
		AttackClass:        "MalformedJWT",
		ParadoxExplanation: "3단 점 분리 규격에 맞지 않는 파손된 JWT 토큰의 유입을 차단했습니다.",
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
				ExpectedReason:   domain.ReasonTokenMalformed,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e08Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *e2e08Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    "not.a.valid.jwt.payload.structure",
		Action:   domain.ActionFileWrite,
		Resource: "output.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-08",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-09: 페이로드 Scope 변조 토큰 차단
type e2e09Scenario struct {
	token string
}

func (s *e2e09Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-09",
		Group:              "G3",
		Name:               "페이로드 Scope 변조 토큰 차단",
		Description:        "정상 발급 후 서명 바이트가 변조되었거나 페이로드가 수정된 토큰은 암호학적 서명 불일치로 차단된다.",
		AttackClass:        "TamperedSignature",
		ParadoxExplanation: "서명 후 페이로드를 임의 수정한 변조 토큰의 암호학적 서명 불일치를 적발했습니다.",
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
				ExpectedReason:   domain.ReasonTokenInvalidSignature,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e09Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{
		TamperSignature: true,
	})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e09Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "output.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-09",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-10: alg: none 공격 차단
type e2e10Scenario struct {
	token string
}

func (s *e2e10Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-10",
		Group:              "G3",
		Name:               "alg: none 공격 차단",
		Description:        "서명 검증을 우회하려는 alg: none 토큰 공격을 Gate 1에서 즉각 차단한다.",
		AttackClass:        "AlgNoneAttack",
		ParadoxExplanation: "서명 검증을 우회하려는 alg: none 취약점 공격 시도를 원천 차단했습니다.",
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
				ExpectedReason:   domain.ReasonTokenAlgNotAllowed,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e10Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{
		TamperAlgNone: true,
	})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e10Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "output.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-10",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-11: typ != at+jwt 불일치 토큰 차단
type e2e11Scenario struct {
	token string
}

func (s *e2e11Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-11",
		Group:              "G3",
		Name:               "typ != at+jwt 불일치 토큰 차단",
		Description:        "RFC 9068 규격에 명시된 at+jwt 외의 typ(예: JWT)을 가진 토큰은 타입 불일치로 차단된다.",
		AttackClass:        "InvalidTypeJWT",
		ParadoxExplanation: "RFC 9068 규격 typ(at+jwt)과 다른 토큰의 인가 경계 진입을 차단했습니다.",
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
				ExpectedReason:   domain.ReasonTokenInvalidType,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e11Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{
		TamperTyp: "JWT",
	})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e11Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "output.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-11",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-12: 서명 키 무중단 회전 후 검증 성공
type e2e12Scenario struct {
	token string
}

func (s *e2e12Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-12",
		Group:              "G3",
		Name:               "서명 키 무중단 회전 후 검증 성공",
		Description:        "구형 활성키로 토큰이 발급된 직후 신규 서명키로 교체(Rotate)되어 구 키가 verify-only 상태가 되어도 정상 인가된다.",
		AttackClass:        "KeyRotationSuccess",
		ParadoxExplanation: "신규 서명키로 교체된 후에도 이전 유효 키(verify-only)로 정상 인가되었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitSuccess,
			File: harness.FileExpectation{
				RelPath:         "rotation_ok.txt",
				ExpectExist:     true,
				ExpectedContent: "rotated key data",
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.allow",
				ExpectedDecision: "allow",
				ExpectedReason:   domain.ReasonAuthorized,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e12Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. Grant 등록
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "rotation_ok.txt"); err != nil {
		return err
	}

	// 2. 현재 활성키로 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok

	// 3. 서명키 회전 (구 키는 verify-only 가 됨)
	if _, err := stack.KeyManager.RotateKey(domain.AuditContext{
		TraceID: "trace-e2e-12-rotate",
		Actor:   "admin",
		Reason:  "rotation test",
	}); err != nil {
		return fmt.Errorf("rotate key: %w", err)
	}

	return nil
}

func (s *e2e12Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "rotation_ok.txt",
		Data:     []byte("rotated key data"),
		TraceID:  "trace-e2e-12",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-13: 폐기된 서명 키(retired) 즉시 거부
type e2e13Scenario struct {
	token string
}

func (s *e2e13Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-13",
		Group:              "G3",
		Name:               "폐기된 서명 키(retired) 즉시 거부",
		Description:        "폐기(Retired) 처리된 서명키로 발급되었던 토큰의 파일 접근 요청은 즉각 무효화되어 차단된다.",
		AttackClass:        "RetiredKeyRejection",
		ParadoxExplanation: "폐기 처리된 이전 서명키로 발급된 토큰의 접근을 즉각 무효화했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "retired.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonTokenKeyRetired,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e13Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. 활성키로 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok

	// 2. 해당 키 ID 조회 후 폐기
	activeKey, err := stack.KeyManager.GetActiveSigningKey()
	if err != nil {
		return err
	}
	if err := stack.KeyManager.RevokeKey(activeKey.KID, domain.AuditContext{
		TraceID: "trace-e2e-13-revoke",
		Actor:   "admin",
		Reason:  "revoke key test",
	}); err != nil {
		return fmt.Errorf("retire key: %w", err)
	}

	return nil
}

func (s *e2e13Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "retired.txt",
		Data:     []byte("fail"),
		TraceID:  "trace-e2e-13",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}
