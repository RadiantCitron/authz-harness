package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/mcp"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

const g9Target = "data/g9-target.txt"

// G9: 서브프로세스 자원·수명 통제 검증 (E2E-40 ~ E2E-44)
func g9Scenarios() []harness.Scenario {
	return []harness.Scenario{
		&g9FaultScenario{id: "E2E-40", name: "멈춘 워커 시간 초과 강제 종료", mode: "hang",
			limits: orchestrator.Limits{Timeout: 300 * time.Millisecond},
			reason: domain.ReasonResourceTimeout, term: orchestrator.TermTimedOut},
		&g9FaultScenario{id: "E2E-41", name: "손자를 남기고 멈춘 워커의 그룹 일괄 소멸", mode: "spawn_child_hang",
			limits: orchestrator.Limits{Timeout: 300 * time.Millisecond},
			reason: domain.ReasonResourceTimeout, term: orchestrator.TermTimedOut, checkGrandchild: true},
		&g9FaultScenario{id: "E2E-42", name: "출력 폭주 워커의 바이트 상한 즉시 차단", mode: "flood",
			limits: orchestrator.Limits{MaxOutputBytes: 16 * 1024},
			reason: domain.ReasonResourceOutputLimit, term: orchestrator.TermOutputExceeded, checkOutputCap: 16 * 1024},
		&e2e43Scenario{},
		&e2e44Scenario{},
	}
}

func g9LimitExpectation(reason domain.Reason) harness.ExpectedAssertion {
	return harness.ExpectedAssertion{
		ExitCode: domain.ExitResourceLimit,
		File:     harness.FileExpectation{RelPath: g9Target, ExpectZeroMutation: true},
		Audit: harness.AuditExpectation{
			RequireEvent:     true,
			ExpectedAction:   orchestrator.AuditActionLimitExceeded,
			ExpectedDecision: "deny",
			ExpectedReason:   reason,
		},
		HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
	}
}

// ----------------------------------------------------------------------------
// E2E-40~42: 결함 워커를 스포너로 직접 감독
// ----------------------------------------------------------------------------
type g9FaultScenario struct {
	id, name, mode  string
	limits          orchestrator.Limits
	reason          domain.Reason
	term            orchestrator.Termination
	checkGrandchild bool
	checkOutputCap  int

	// pidOverride 는 변이 검증(TC-050-03)에서만 쓰는 시험 주입점이다.
	pidOverride func(real int) int
}

func (s *g9FaultScenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 s.id,
		Group:              "G9",
		Name:               s.name,
		Description:        fmt.Sprintf("결함 워커(-mode %s)를 부모 스포너가 한계(%+v)로 감독하여 강제 종료한다.", s.mode, s.limits),
		AttackClass:        "ResourceExhaustion",
		ParadoxExplanation: "인가 판정과 별개로, 부모가 시간·출력 한계를 넘은 워커와 그 자식 전체를 끝냈습니다.",
		RequiresSubprocess: true,
		Expected:           g9LimitExpectation(s.reason),
	}
}

func (s *g9FaultScenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *g9FaultScenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	sp, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath: env.FaultWorkerPath,
		Args:       []string{"-mode", s.mode},
		Limits:     s.limits,
		Audit:      stack.AuditWriter,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	res, err := sp.Spawn(ctx, subagent.SubagentRequest{
		Version: "1.0", TraceID: "trace-" + strings.ToLower(s.id), Action: string(domain.ActionFileRead), FilePath: g9Target,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	code := domain.ExitCode(res.ExitCode)

	if res.Termination != s.term {
		return code, harness.Invariantf("termination = %s, want %s", res.Termination, s.term)
	}
	if res.Duration >= 3*time.Second {
		return code, harness.Invariantf("duration %v >= 3s (한계가 아니라 다른 사유로 끝났을 가능성)", res.Duration)
	}
	if s.checkOutputCap > 0 && len(res.StdoutRaw) > s.checkOutputCap {
		return code, harness.Invariantf("stdout %d bytes exceeds cap %d", len(res.StdoutRaw), s.checkOutputCap)
	}
	if s.checkGrandchild {
		m := regexp.MustCompile(`CHILD_PID=(\d+)`).FindStringSubmatch(res.StdoutRaw)
		if m == nil {
			return code, harness.Invariantf("CHILD_PID not found in stdout")
		}
		pid, _ := strconv.Atoi(m[1])
		if s.pidOverride != nil {
			pid = s.pidOverride(pid)
		}
		if !harness.WaitForProcessGone(pid, time.Second) {
			return code, harness.Invariantf("grandchild pid %d still alive after group kill", pid)
		}
	}
	return code, nil
}

// ----------------------------------------------------------------------------
// E2E-43: MCP tools/call 경로의 시간 초과와 토큰 비노출
// ----------------------------------------------------------------------------
type e2e43Scenario struct{ token string }

func (s *e2e43Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-43",
		Group:              "G9",
		Name:               "MCP tools/call 시간 초과와 토큰 비노출",
		Description:        "MCP 어댑터가 멈춘 워커를 시간 초과로 끝내고 구조화 오류(exit 17)를 반환하되 토큰을 노출하지 않는다.",
		AttackClass:        "ResourceExhaustion",
		ParadoxExplanation: "도구 호출이 멈춰도 부모가 한계를 강제하고, 응답에는 원시 토큰이 실리지 않습니다.",
		RequiresSubprocess: true,
		Expected:           g9LimitExpectation(domain.ReasonResourceTimeout),
	}
}

func (s *e2e43Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, g9Target); err != nil {
		return err
	}
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read:"+g9Target, 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e43Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	sp, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath: env.FaultWorkerPath,
		Args:       []string{"-mode", "hang"},
		Limits:     orchestrator.Limits{Timeout: 300 * time.Millisecond},
		Audit:      stack.AuditWriter,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, resp, err := executeMCPCall(ctx, env, stack, sp, "file_read", map[string]any{"path": g9Target}, s.token, false)
	if err != nil {
		return code, err
	}

	raw, mErr := json.Marshal(resp)
	if mErr != nil {
		return domain.ExitInternalError, mErr
	}
	if mcp.ContainsRawToken(string(raw)) || strings.Contains(string(raw), s.token) {
		return code, harness.Invariantf("raw token leaked in MCP response")
	}
	res, _ := resp.Result.(map[string]any)
	if isErr, _ := res["isError"].(bool); !isErr {
		return code, harness.Invariantf("isError is not true")
	}
	if !strings.Contains(string(raw), "["+string(domain.ReasonResourceTimeout)+"]") {
		return code, harness.Invariantf("response text lacks [RESOURCE_TIMEOUT]")
	}
	return code, nil
}

// ----------------------------------------------------------------------------
// E2E-44: 기본 한계 아래 정상 위임 워커 비회귀
// ----------------------------------------------------------------------------
type e2e44Scenario struct{ token string }

func (s *e2e44Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-44",
		Group:              "G9",
		Name:               "기본 한계 아래 정상 위임 워커 비회귀",
		Description:        "기본 Limits 로 감독해도 정상 워커는 자진 종료(exit 0)하고 PEP 허용 판정이 유지된다.",
		AttackClass:        "정상",
		ParadoxExplanation: "감독 계층이 정상 워커를 오탐으로 끊지 않음을 증명합니다.",
		RequiresSubprocess: true,
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitSuccess,
			// 읽기 시나리오이므로 파일은 기준 내용 그대로여야 한다 (0바이트 가정 대신 내용 고정).
			File: harness.FileExpectation{RelPath: g9Target, ExpectExist: true, ExpectedContent: "g9 baseline"},
			Audit: harness.AuditExpectation{
				RequireEvent:     true,
				ExpectedAction:   "pep.allow",
				ExpectedDecision: "allow",
				ExpectedReason:   domain.ReasonAuthorized,
			},
			HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
		},
	}
}

func (s *e2e44Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()
	if err := stack.Jail.WriteFile(g9Target, []byte("g9 baseline")); err != nil {
		return err
	}
	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, g9Target); err != nil {
		return err
	}
	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read:"+g9Target, 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e44Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	sp, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath: env.BinaryPath,
		Args: []string{
			"subagent", "worker",
			"-workspace", env.WorkspaceDir,
			"-state-file", env.StatePath,
			"-pub-jwks-file", env.PubJWKSPath,
			"-replay-file", env.ReplayPath,
			"-audit-file", env.AuditPath,
		},
		Limits: orchestrator.DefaultLimits(),
		Audit:  stack.AuditWriter,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	res, err := sp.Spawn(ctx, subagent.SubagentRequest{
		Version: "1.0", TraceID: "trace-e2e-44", Token: s.token,
		Action: string(domain.ActionFileRead), FilePath: g9Target,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	code := domain.ExitCode(res.ExitCode)
	if res.Termination != orchestrator.TermExited || res.RawExitCode != 0 {
		return code, harness.Invariantf("termination=%s raw_exit=%d, want exited/0", res.Termination, res.RawExitCode)
	}
	return code, nil
}
