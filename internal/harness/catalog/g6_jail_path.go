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

// G6: Workspace Jail 파일 격리 및 경로 순회 탈출 방어 (E2E-25 ~ E2E-27)
func g6Scenarios() []harness.Scenario {
	return []harness.Scenario{
		&e2e25Scenario{},
		&e2e26Scenario{},
		&e2e27Scenario{},
	}
}

// E2E-25: 상대 경로 탈출(../../etc/passwd) 차단
type e2e25Scenario struct {
	token string
}

func (s *e2e25Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-25",
		Group:              "G6",
		Name:               "상대 경로 탈출(../../etc/passwd) 차단",
		Description:        "상대 경로(../)를 통해 격리 작업공간 외부에 접근하려는 순회 시도는 Gate 2c Jail에서 차단된다.",
		AttackClass:        "PathTraversal",
		ParadoxExplanation: "상대 경로(../)를 통한 Workspace Jail 외부 디렉터리 접근 탈출을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitPathViolation,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonPathTraversal,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e25Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	// Grant 및 Scope 와 무관하게 파일 경로 자체에 .. 탈출이 있으므로
	// PDP 가 해당 경로에 대해 Grant 부재로 거부하지 않도록 와일드카드 또는 상대 경로 허용 세팅이 필요한지 점검
	// 여기서는 worker-01 에게 와일드카드 또는 기본 Grant 를 부여하되, PEP 가 PDP 통과 후 Jail 에서 차단하도록 설계
	// stateStore 에 직접 Grant 추가 (상위 탈출 경로)
	st, err := stack.StateStore.Load()
	if err != nil {
		return err
	}
	st.Grants = append(st.Grants, domain.Grant{
		ID:        "grant-e2e-25",
		Subject:   "worker-01",
		Action:    domain.ActionFileWrite,
		Resource:  "../../etc/passwd",
		Status:    domain.GrantStatusActive,
		CreatedAt: env.MockClock.Now(),
	})
	if err := stack.StateStore.Save(st); err != nil {
		return err
	}

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e25Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	return executeHarnessAction(ctx, env, stack, ActionRequest{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "../../etc/passwd",
		Data:     []byte("malicious traversal"),
		TraceID:  "trace-e2e-25",
	})
}

// E2E-26: 루트 접두사 착시(/workspace-evil) 차단
type e2e26Scenario struct {
	token string
}

func (s *e2e26Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-26",
		Group:              "G6",
		Name:               "루트 접두사 착시(/workspace-evil) 차단",
		Description:        "루트 경로 문자열 접두사 일치 트릭(strings.HasPrefix)을 이용한 인접 디렉터리 침범은 차단된다.",
		AttackClass:        "PrefixIllusion",
		ParadoxExplanation: "루트 경로 접두사 일치 트릭을 이용한 인접 디렉터리 침범을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitPathViolation,
			File: harness.FileExpectation{
				RelPath:            "output.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonPathTraversal,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e26Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	evilPath := env.WorkspaceDir + "-evil/secret.txt"
	st, err := stack.StateStore.Load()
	if err != nil {
		return err
	}
	st.Grants = append(st.Grants, domain.Grant{
		ID:        "grant-e2e-26",
		Subject:   "worker-01",
		Action:    domain.ActionFileWrite,
		Resource:  evilPath,
		Status:    domain.GrantStatusActive,
		CreatedAt: env.MockClock.Now(),
	})
	if err := stack.StateStore.Save(st); err != nil {
		return err
	}

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e26Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	evilPath := env.WorkspaceDir + "-evil/secret.txt"
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: evilPath,
		Data:     []byte("prefix attack"),
		TraceID:  "trace-e2e-26",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// E2E-27: 심볼릭 링크 외부 탈출 시도 차단
type e2e27Scenario struct {
	token string
}

func (s *e2e27Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-27",
		Group:              "G6",
		Name:               "심볼릭 링크 외부 탈출 시도 차단",
		Description:        "작업공간 내부에서 외부 민감 파일을 가리키는 심볼릭 링크를 통한 탈출 시도는 filepath.EvalSymlinks 검증에서 차단된다.",
		AttackClass:        "SymlinkEscape",
		ParadoxExplanation: "외부 민감 파일을 가리키는 심볼릭 링크를 통한 PEP Jail 탈출을 차단했습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitPathViolation,
			File: harness.FileExpectation{
				RelPath:            "link_target_file.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.deny",
				ExpectedDecision: "deny",
				ExpectedReason:   domain.ReasonSymlinkEscape,
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e27Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}

	// 1. 격리 외부 호스트 타깃 파일 생성
	outsideFile := filepath.Join(env.RootDir, "outside_secret.txt")
	if err := os.WriteFile(outsideFile, []byte("outside secret"), 0600); err != nil {
		return err
	}

	// 2. 작업공간 내부에 외부를 가리키는 심볼릭 링크 생성
	linkPath := filepath.Join(env.WorkspaceDir, "link_to_host.txt")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		return fmt.Errorf("create symlink: %w", err)
	}

	// 3. Grant 및 토큰 발급
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "link_to_host.txt"); err != nil {
		return err
	}

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:write", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e27Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}

	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token:    s.token,
		Action:   domain.ActionFileWrite,
		Resource: "link_to_host.txt",
		Data:     []byte("jail escape attempt"),
		TraceID:  "trace-e2e-27",
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}
