package catalog

import (
	"context"
	"os"
	"strings"
	"time"

	"authz-harness/internal/audit"
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
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonMissingTraceContext,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
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

	// 유효한 Action 및 Resource 를 주되, TraceID 를 누락하고 RequireTraceID 를 설정하여 실제 trace_id 누락 차단 검증
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:          s.token,
		Action:         domain.ActionFileWrite,
		Resource:       "output.txt",
		Data:           []byte("fail"),
		TraceID:        "",
		RequireTraceID: true,
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
			ExitCode: domain.ExitAuditFailure,
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
				RequireValidChain: false, // 사후 검증(audit.VerifyHashChain)에서 이미 적발 완료되었음을 증명
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
	if !res.Allowed {
		return res.ExitCode, nil
	}

	// 2. 실행 후 audit.jsonl 파일의 내용을 읽어 유효한 JSON 형식 내의 특정 필드 변조 (공격자 임의 조작 시뮬레이션)
	data, err := os.ReadFile(env.AuditPath)
	if err != nil {
		return domain.ExitInternalError, err
	}
	tampered := strings.Replace(string(data), `"resource":"audit_tamper.txt"`, `"resource":"tampered.txt"`, 1)
	if err := os.WriteFile(env.AuditPath, []byte(tampered), 0600); err != nil {
		return domain.ExitInternalError, err
	}

	// 3. 변조 직후 사후 감사 무결성 검증기 직접 호출
	verifyErr := audit.VerifyHashChain(env.AuditPath)

	// 4. 변조 적발 시 ExitAuditFailure (15) 반환
	return domain.ExitCodeFromError(verifyErr, domain.ExitSuccess), nil
}
