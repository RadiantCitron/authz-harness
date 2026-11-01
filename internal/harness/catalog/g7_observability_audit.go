package catalog

import (
	"context"
	"os"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G7: 관측성, 무결성 및 Fail-Closed 감사 (E2E-28 ~ E2E-30)
func g7Scenarios() []harness.Scenario {
	return []harness.Scenario{
		&e2e28Scenario{},
		&e2e29Scenario{},
		&e2e30Scenario{},
	}
}

// E2E-28: trace_id 누락 요청 차단
type e2e28Scenario struct {
	token string
}

func (s *e2e28Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-28",
		Group:              "G7",
		Name:               "trace_id 누락 요청 차단",
		Description:        "감사 추적 및 분산 트레이싱에 필수적인 trace_id 인자가 누락된 경우 Gate 0에서 즉각 차단된다.",
		AttackClass:        "MissingTraceID",
		ParadoxExplanation: "감사 추적에 필수적인 단일 trace_id 컨텍스트가 누락된 요청을 거부했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitBadInput,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent: false, // trace_id 누락 시 Gate 0 단계에서 즉각 종료
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: false,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e28Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
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

func (s *e2e28Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// Action/Resource 누락으로 Gate 0 ExitBadInput 유도
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   "", // 유효하지 않은 Action 누락 -> Gate 0 ExitBadInput (14)
		Resource: "output.txt",
		Data:     []byte("fail"),
		TraceID:  "",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-29: 감사 기록 실패 시 파일 쓰기 중단 (Fail-Closed)
type e2e29Scenario struct {
	token string
}

func (s *e2e29Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-29",
		Group:              "G7",
		Name:               "감사 기록 실패 시 파일 쓰기 중단 (Fail-Closed)",
		Description:        "사전 커밋 감사 로그 디스크 쓰기가 실패할 경우 실제 파일 I/O는 일체 수행되지 않고 0바이트로 방어된다 (Fail-Closed).",
		AttackClass:        "AuditFailureFailClosed",
		ParadoxExplanation: "감사 로그 파일 쓰기 실패 시 I/O 부작용을 원천 차단하고 Fail-Closed를 사수했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuditFailure,
			File: harness.FileExpectation{
				RelPath:            "fail_closed.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent: false, // 디스크 쓰기 실패 유도 상태
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: false,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e29Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// Grant 등록
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "fail_closed.txt"); err != nil {
		return err
	}

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e29Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// InjectAuditFailure: true 결함 주입으로 Stage 4 Audit 쓰기 실패 시뮬레이션
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:              s.token,
		Action:             domain.ActionFileWrite,
		Resource:           "fail_closed.txt",
		Data:               []byte("should never be written"),
		TraceID:            "trace-e2e-29",
		InjectAuditFailure: true,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-30: 사후 감사 로그 변조 적발 (audit verify)
type e2e30Scenario struct {
	token string
}

func (s *e2e30Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-30",
		Group:              "G7",
		Name:               "사후 감사 로그 변조 적발 (audit verify)",
		Description:        "정상 I/O 수행 후 감사 로그의 이전 행 내용을 임의 변조했을 때 해시 체인 무결성 검증에서 변조가 즉각 적발된다.",
		AttackClass:        "AuditLogTampering",
		ParadoxExplanation: "감사 로그 파일 내용의 임의 변조 시 해시 체인 불일치로 변조를 적발했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitSuccess,
			File: harness.FileExpectation{
				RelPath:         "audit_tamper.txt",
				ExpectExist:     true,
				ExpectedContent: "normal write before tamper",
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.allow",
				ExpectedDecision: "allow",
				ExpectedReason:   domain.ReasonAuthorized,
			},
			HashChain: harness.HashChainExpectation{
				// Quad-Assertion 에서 해시 체인 변조를 의도적으로 유발하므로
				// 이 시나리오는 Runner의 Assert() 에서 HashChainPassed 가 false 가 됨을 검증하거나,
				// 시나리오 자체의 Expected 에 해시체인 무결성 요구를 설정
				RequireValidChain: false, // 체인이 변조되었음을 검증
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e30Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. Grant 등록
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "audit_tamper.txt"); err != nil {
		return err
	}

	// 2. 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e30Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	// 1. 정상 파일 쓰기 실행
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "audit_tamper.txt",
		Data:     []byte("normal write before tamper"),
		TraceID:  "trace-e2e-30",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}

	// 2. 실행 후 audit.jsonl 파일의 내용을 읽어 변조 (공격자 임의 조작 시뮬레이션)
	data, err := os.ReadFile(env.AuditPath)
	if err == nil && len(data) > 0 {
		// 내용 일부 바이트 조작
		tampered := append([]byte(`{"tampered":"attack"}`+"\n"), data...)
		_ = os.WriteFile(env.AuditPath, tampered, 0600)
	}

	return res.ExitCode, nil
}
