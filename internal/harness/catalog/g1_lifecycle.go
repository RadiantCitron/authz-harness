package catalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G1: 정상 생명주기 및 동적 권한 회수 (E2E-01 ~ E2E-03)
func g1Scenarios() []harness.Scenario {
	return []harness.Scenario{
		&e2e01Scenario{},
		&e2e02Scenario{},
		&e2e03Scenario{},
	}
}

// E2E-01: 정상 단일 파일 읽기
type e2e01Scenario struct {
	token string
}

func (s *e2e01Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-01",
		Group:              "G1",
		Name:               "정상 단일 파일 읽기",
		Description:        "유효한 토큰과 파일 읽기 권한(Grant)을 가진 주체가 격리 작업공간 내 파일을 정상적으로 읽는다.",
		AttackClass:        "HappyPath",
		ParadoxExplanation: "파일 읽기 권한이 정상 부여되어 파일을 성공적으로 읽었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitSuccess,
			File: harness.FileExpectation{
				RelPath:         "hello.txt",
				ExpectExist:     true,
				ExpectedContent: "hello world",
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

func (s *e2e01Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. 파일 준비
	filePath := filepath.Join(env.WorkspaceDir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello world"), 0600); err != nil {
		return fmt.Errorf("write test file: %w", err)
	}

	// 2. Grant 등록
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, "hello.txt"); err != nil {
		return fmt.Errorf("grant permission: %w", err)
	}

	// 3. 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return fmt.Errorf("issue token: %w", err)
	}
	s.token = tok
	return nil
}

func (s *e2e01Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileRead,
		Resource: "hello.txt",
		TraceID:  "trace-e2e-01",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-02: 정상 단일 파일 쓰기
type e2e02Scenario struct {
	token string
}

func (s *e2e02Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-02",
		Group:              "G1",
		Name:               "정상 단일 파일 쓰기",
		Description:        "유효한 토큰과 쓰기 권한(Grant)을 가진 주체가 격리 작업공간 내 새 파일을 안전하게 작성한다.",
		AttackClass:        "HappyPath",
		ParadoxExplanation: "파일 쓰기 권한이 정상 부여되어 지정된 위치에 파일을 안전하게 작성했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitSuccess,
			File: harness.FileExpectation{
				RelPath:         "output.txt",
				ExpectExist:     true,
				ExpectedContent: "secure data written",
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

func (s *e2e02Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. Grant 등록
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "output.txt"); err != nil {
		return fmt.Errorf("grant permission: %w", err)
	}

	// 2. 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return fmt.Errorf("issue token: %w", err)
	}
	s.token = tok
	return nil
}

func (s *e2e02Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "output.txt",
		Data:     []byte("secure data written"),
		TraceID:  "trace-e2e-02",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-03: 동적 전환 [거부→허용→회수 후 즉시 거부]
type e2e03Scenario struct {
	token string
}

func (s *e2e03Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-03",
		Group:              "G1",
		Name:               "동적 전환 [거부→허용→회수 후 즉시 거부]",
		Description:        "권한이 동적으로 부여되었다가 회수(Revoke)되었을 때, 기존 토큰으로 쓰기를 시도하면 즉시 인가가 차단되고 파일 쓰기가 0바이트 유지된다.",
		AttackClass:        "DynamicRevocation",
		ParadoxExplanation: "Grant가 실시간 회수되었을 때 즉시 인가를 차단하여 잔여 쓰기를 방어했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "revoked.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonGrantRevoked,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e03Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. Grant 발급
	g, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "revoked.txt")
	if err != nil {
		return fmt.Errorf("grant permission: %w", err)
	}

	// 2. 토큰 발급
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return fmt.Errorf("issue token: %w", err)
	}
	s.token = tok

	// 3. Grant 즉시 회수
	if _, err := stack.PAP.RevokeGrant(ctx, g.ID); err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}

	return nil
}

func (s *e2e03Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "revoked.txt",
		Data:     []byte("should not be written"),
		TraceID:  "trace-e2e-03",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}
