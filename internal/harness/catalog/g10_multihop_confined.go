package catalog

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/orchestrator"
)

// E2E-80: 다단계 위임의 마지막 워커를 OS 격리 아래에서 기동 (계획 048)
//
// 정직한 2-Hop 위임이 커널 격리(Seatbelt) 아래에서도 그대로 성공하고, 격리를 적용했다는 사실이
// 부모의 감사에 남는다. 악의 워커의 직접 접근 차단은 E2E-45~49가 증명하므로 여기서 반복하지 않는다.
type e2e80Scenario struct {
	rootToken string
}

func g10MultiHopScenarios() []harness.Scenario {
	return []harness.Scenario{&e2e80Scenario{}}
}

func (s *e2e80Scenario) traceID() string { return "trace-e2e-80" }

func (s *e2e80Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                  "E2E-80",
		Group:               "G10",
		Name:                "2-Hop 다단계 위임의 마지막 워커를 OS 격리 아래에서 실행",
		Description:         "루트 → 중간 관리자 → 최종 워커로 이어지는 연쇄 위임에서, 마지막 워커 프로세스를 커널 격리 아래에서 기동해도 정상 위임·파일 쓰기가 성공하고 격리 적용 사실이 감사에 남는다.",
		AttackClass:         "OSConfinementMultiHop",
		ParadoxExplanation:  "격리는 정직한 다단계 위임을 막지 않으면서, 마지막 워커가 커널 격리 아래에서 기동되었다는 사실을 부모가 감사로 남겼습니다.",
		RequiresSubprocess:  true,
		RequiresConfinement: true,
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitSuccess,
			File: harness.FileExpectation{
				RelPath:         "multihop_confined.txt",
				ExpectExist:     true,
				ExpectedContent: "multihop confined success",
			},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   orchestrator.AuditActionAgentConfined,
				ExpectedDecision: "allow",
				ExpectedTraceID:  s.traceID(),
			},
			HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
		},
	}
}

func (s *e2e80Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	if err := precreateAuditLock(env); err != nil {
		return err
	}
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()

	// 최종 워커가 쓰기 전에 대상 파일이 이미 있어야 하는 도구 계약은 없으므로 만들지 않는다.
	// 쓰기 권한만 최종 워커에게 부여한다.
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "multihop_confined.txt"); err != nil {
		return fmt.Errorf("grant worker-01: %w", err)
	}
	tok, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01", "orchestrator-root", "file:read file:write", 30*time.Minute, token.IssueOptions{})
	if err != nil {
		return fmt.Errorf("issue root token: %w", err)
	}
	s.rootToken = tok
	return nil
}

func (s *e2e80Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	pol := confinement.WorkerPolicy(env.RootDir, env.WorkspaceDir, filepath.Dir(env.StatePath), env.AuditPath)
	spawner, err := orchestrator.NewMultiHopSpawner(orchestrator.MultiHopConfig{
		BinaryPath:   env.BinaryPath,
		WorkspaceDir: env.WorkspaceDir,
		StatePath:    env.StatePath,
		PubJWKSPath:  env.PubJWKSPath,
		ReplayPath:   env.ReplayPath,
		AuditPath:    env.AuditPath,
		Audit:        stack.AuditWriter,
		Gateway:      stack.PEP,
		Confiner:     confinement.WithLauncher(confinement.Platform(), env.BinaryPath),
		Confinement:  pol,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return spawner.ExecuteMultiHop(ctx, orchestrator.MultiHopDelegationRequest{
		TraceID:       s.traceID(),
		RootToken:     s.rootToken,
		LeadSubject:   "lead-01",
		LeadScope:     "file:read file:write",
		WorkerSubject: "worker-01",
		WorkerScope:   "file:write",
		TargetFile:    "multihop_confined.txt",
		Action:        domain.ActionFileWrite,
		Data:          []byte("multihop confined success"),
		Exchange:      stack.ExchangeService,
	})
}
