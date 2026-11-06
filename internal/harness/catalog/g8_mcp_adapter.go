package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/mcp"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// G8: MCP/Tool-Call 보안 게이트웨이 어댑터 검증 (E2E-33 ~ E2E-39)
func g8Scenarios() []harness.Scenario {
	return withStages([]harness.Scenario{
		&e2e33Scenario{},
		&e2e34Scenario{},
		&e2e35Scenario{},
		&e2e36Scenario{},
		&e2e37Scenario{},
		&e2e38Scenario{},
		&e2e39Scenario{},
	})
}

// newMCPSpawner 는 MCP 호출 경로가 사용할 표준 Spawner 를 조립한다 (G8·G9 공유).
// 바이너리가 있으면 프로덕션 서브프로세스 워커, 없으면 InProc 브릿지를 쓴다.
func newMCPSpawner(env *harness.SandboxEnvironment, stack *harnessStack) (orchestrator.Spawner, error) {
	if env.BinaryPath != "" {
		return orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
			BinaryPath: env.BinaryPath,
			Args:       orchestrator.WorkerArgs(env.WorkspaceDir, env.StatePath, env.PubJWKSPath, env.ReplayPath, env.AuditPath, "", false),
			Audit:      stack.AuditWriter,
		})
	}
	return &inProcSpawnerBridge{stack: stack}, nil
}

// executeMCPCall 은 샌드박스 환경에서 MCP JSON-RPC tools/call 요청을 실행하고 종료 코드 및 응답을 수거한다.
func executeMCPCall(
	ctx context.Context,
	env *harness.SandboxEnvironment,
	stack *harnessStack,
	spawner orchestrator.Spawner,
	toolName string,
	arguments map[string]any,
	tokenVal string,
	omitToken bool,
) (domain.ExitCode, *mcp.JSONRPCResponse, error) {
	// tools/call 요청 프레임 구성
	callParams := map[string]any{
		"name":      toolName,
		"arguments": arguments,
	}
	if !omitToken {
		callParams["_meta"] = map[string]any{
			"authz_token": tokenVal,
		}
	}

	rpcReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      "mcp-test-call-1",
		"method":  "tools/call",
		"params":  callParams,
	}

	reqBytes, err := json.Marshal(rpcReq)
	if err != nil {
		return domain.ExitInternalError, nil, err
	}
	reqBytes = append(reqBytes, '\n')

	inBuf := bytes.NewReader(reqBytes)
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}

	executor := mcp.NewSubprocessExecutor(spawner)
	server := mcp.NewServer(inBuf, outBuf, errBuf, executor, nil)

	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		return domain.ExitInternalError, nil, err
	}

	// 응답 파싱
	line, err := outBuf.ReadBytes('\n')
	if err != nil {
		return domain.ExitInternalError, nil, fmt.Errorf("no output from mcp server: %w (stderr: %s)", err, errBuf.String())
	}

	var resp mcp.JSONRPCResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return domain.ExitInternalError, nil, fmt.Errorf("invalid jsonrpc response: %w", err)
	}

	code, err := exitCodeFromResponse(&resp)
	return code, &resp, err
}

// exitCodeFromResponse 는 JSON-RPC 응답에서 종료 코드를 구조적으로 읽는다.
// 프로토콜 에러는 ExitBadInput, 도구 거부는 structuredContent.exit_code 를 사용하며,
// 구조화 정보가 없거나 형식이 틀리면 fail-closed 로 ExitInternalError 를 반환한다.
func exitCodeFromResponse(resp *mcp.JSONRPCResponse) (domain.ExitCode, error) {
	if resp.Error != nil {
		return domain.ExitBadInput, nil
	}
	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		if resp.Result == nil {
			return domain.ExitInternalError, fmt.Errorf("mcp response has neither result nor error")
		}
		return domain.ExitInternalError, fmt.Errorf("mcp result has unexpected type %T", resp.Result)
	}
	isErr, _ := resMap["isError"].(bool)
	if !isErr {
		return domain.ExitSuccess, nil
	}
	sc, ok := resMap["structuredContent"].(map[string]any)
	if !ok {
		return domain.ExitInternalError, fmt.Errorf("mcp isError result lacks structuredContent")
	}
	n, ok := sc["exit_code"].(float64)
	if !ok || n != float64(int(n)) {
		return domain.ExitInternalError, fmt.Errorf("mcp structuredContent.exit_code is not an integer")
	}
	return domain.ExitCode(int(n)), nil
}

type inProcSpawnerBridge struct {
	stack *harnessStack
}

// Spawn 은 subprocess 모드와 같은 프로덕션 워커(subagent.SubagentWorker)를 프로세스 안에서 실행한다.
// 응답 조립·거부 사유·음수 시계 오프셋 거부는 모두 워커의 규칙을 그대로 따른다(재작성 금지).
func (b *inProcSpawnerBridge) Spawn(ctx context.Context, req subagent.SubagentRequest) (*orchestrator.SpawnResult, error) {
	worker, err := subagent.NewWorker(b.stack.PEP)
	if err != nil {
		return nil, fmt.Errorf("create inproc worker: %w", err)
	}
	resp, exitCode := worker.Execute(ctx, req)
	return &orchestrator.SpawnResult{
		TraceID:  req.TraceID,
		ExitCode: exitCode,
		Response: &resp,
	}, nil
}

// ----------------------------------------------------------------------------
// E2E-33: MCP 읽기 토큰으로 file_read 정상 호출 (ExitCode: 0)
// ----------------------------------------------------------------------------
type e2e33Scenario struct {
	token string
}

func (s *e2e33Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-33",
		Group:              "G8",
		Name:               "MCP 읽기 토큰으로 file_read 정상 호출",
		Description:        "외부 에이전트가 MCP stdio tools/call 로 유효한 읽기 토큰과 함께 파일 읽기를 요청하면 격리 서브프로세스를 거쳐 파일 내용을 정상 반환한다.",
		AttackClass:        "NormalDelegation",
		ParadoxExplanation: "MCP 어댑터가 서브프로세스 worker 에 토큰을 위임 전달하여 PEP 단일 입출구에서 정상 허가되었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitSuccess,
			File: harness.FileExpectation{
				RelPath:         "mcp_task.txt",
				ExpectExist:     true,
				ExpectedContent: "mcp test data content",
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

func (s *e2e33Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()

	if err := stack.Jail.WriteFile("mcp_task.txt", []byte("mcp test data content")); err != nil {
		return err
	}

	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, "mcp_task.txt"); err != nil {
		return err
	}

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read:mcp_task.txt", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e33Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	spawner, err := newMCPSpawner(env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, _, err := executeMCPCall(ctx, env, stack, spawner, "file_read", map[string]any{"path": "mcp_task.txt"}, s.token, false)
	return code, err
}

// ----------------------------------------------------------------------------
// E2E-34: MCP 읽기 토큰으로 file_write 시도 차단 (ExitCode: 12)
// ----------------------------------------------------------------------------
type e2e34Scenario struct {
	token string
}

func (s *e2e34Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-34",
		Group:              "G8",
		Name:               "MCP 읽기 토큰으로 file_write 시도 차단",
		Description:        "읽기 권한만 부여된 MCP 호출자가 쓰기(file_write)를 호출하면 서브프로세스 PEP 에서 스코프 불충분으로 차단된다.",
		AttackClass:        "PrivilegeEscalation",
		ParadoxExplanation: "읽기 전용 위임 토큰으로 도구 호출 시 쓰기를 시도했으나 자식 PEP 에서 안전 차단되었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "mcp_protected.txt",
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

func (s *e2e34Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()

	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, "mcp_protected.txt"); err != nil {
		return err
	}

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read:mcp_protected.txt", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e34Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	spawner, err := newMCPSpawner(env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, _, err := executeMCPCall(ctx, env, stack, spawner, "file_write", map[string]any{"path": "mcp_protected.txt", "data": "tampered"}, s.token, false)
	return code, err
}

// ----------------------------------------------------------------------------
// E2E-35: 만료된 토큰으로 MCP tools/call 호출 차단 (ExitCode: 11)
// ----------------------------------------------------------------------------
type e2e35Scenario struct {
	token string
}

func (s *e2e35Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-35",
		Group:              "G8",
		Name:               "만료된 토큰으로 MCP tools/call 호출 차단",
		Description:        "유효기간이 만료된 토큰으로 MCP tools/call 을 호출하면 서브프로세스 토큰 검증기에서 즉시 거부된다.",
		AttackClass:        "ExpiredTokenReplay",
		ParadoxExplanation: "만료된 JWT 토큰은 암호 서명이 유효하더라도 만료시각 경과로 즉각 차단되었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitTokenInvalid,
			File: harness.FileExpectation{
				RelPath:            "mcp_expired.txt",
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

func (s *e2e35Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()

	if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, "mcp_expired.txt"); err != nil {
		return err
	}

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read:mcp_expired.txt", 10*time.Minute, token.IssueOptions{
		TamperExpired: true,
	})
	if err != nil {
		return err
	}
	s.token = tok
	return nil
}

func (s *e2e35Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	spawner, err := newMCPSpawner(env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, _, err := executeMCPCall(ctx, env, stack, spawner, "file_read", map[string]any{"path": "mcp_expired.txt"}, s.token, false)
	return code, err
}

// ----------------------------------------------------------------------------
// E2E-36: MCP tools/call 경로 순회(../../) 탈출 차단 (ExitCode: 13)
// ----------------------------------------------------------------------------
type e2e36Scenario struct {
	token string
}

func (s *e2e36Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-36",
		Group:              "G8",
		Name:               "MCP tools/call 경로 순회(../../) 탈출 차단",
		Description:        "MCP 인자 path 에 ../../etc/passwd 와 같은 탈출 경로가 전달되면 Jail 경계 검증에서 즉시 차단된다.",
		AttackClass:        "PathTraversal",
		ParadoxExplanation: "MCP 호출 인자에 상위 순회 경로가 포함되어 Jail 파일 격리 관문에서 차단되었습니다.",
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

func (s *e2e36Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()

	st, err := stack.StateStore.Load()
	if err != nil {
		return err
	}
	st.Grants = append(st.Grants, domain.Grant{
		ID:        "grant-mcp-escape",
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

func (s *e2e36Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	spawner, err := newMCPSpawner(env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, _, err := executeMCPCall(ctx, env, stack, spawner, "file_write", map[string]any{"path": "../../etc/passwd", "data": "injected"}, s.token, false)
	return code, err
}

// ----------------------------------------------------------------------------
// E2E-37: Grant 회수 후 MCP tools/call 실시간 차단 (ExitCode: 12)
// ----------------------------------------------------------------------------
type e2e37Scenario struct {
	token   string
	grantID string
}

func (s *e2e37Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-37",
		Group:              "G8",
		Name:               "Grant 회수 후 MCP tools/call 실시간 차단",
		Description:        "토큰 자체의 유효기간이 남아있더라도 중앙 상태에서 해당 Grant 가 회수되면 PDP 실시간 조회에서 즉각 거부된다.",
		AttackClass:        "GrantRevocation",
		ParadoxExplanation: "토큰 암호 서명이 유효하더라도 활성 Grant 가 회수되어 실시간 인가 거부되었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitAuthzDenied,
			File: harness.FileExpectation{
				RelPath:            "mcp_revoked.txt",
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

func (s *e2e37Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()

	g, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, "mcp_revoked.txt")
	if err != nil {
		return err
	}
	s.grantID = g.ID

	tok, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read:mcp_revoked.txt", 10*time.Minute, token.IssueOptions{})
	if err != nil {
		return err
	}
	s.token = tok

	// Grant 회수
	if _, err := stack.PAP.RevokeGrant(ctx, s.grantID); err != nil {
		return err
	}
	return nil
}

func (s *e2e37Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	spawner, err := newMCPSpawner(env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, _, err := executeMCPCall(ctx, env, stack, spawner, "file_read", map[string]any{"path": "mcp_revoked.txt"}, s.token, false)
	return code, err
}

// ----------------------------------------------------------------------------
// E2E-38: _meta.authz_token 누락 MCP 호출 차단 (ExitCode: 14)
// ----------------------------------------------------------------------------
type e2e38Scenario struct{}

func (s *e2e38Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-38",
		Group:              "G8",
		Name:               "_meta.authz_token 누락 MCP 호출 차단",
		Description:        "tools/call 요청에 _meta.authz_token 이 누락되면 어댑터 프레임 검증 관문에서 자식 프로세스를 기동하지 않고 즉각 차단된다.",
		AttackClass:        "MissingAuthentication",
		ParadoxExplanation: "인증 토큰이 누락된 비신뢰 호출은 자식 프로세스 기동 전 어댑터 스키마에서 거부되었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitBadInput,
			File: harness.FileExpectation{
				RelPath:            "mcp_notoken.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent: false, // 자식 서브프로세스 미기동으로 감사 로그 기록 없음
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e38Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *e2e38Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	spawner, err := newMCPSpawner(env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, _, err := executeMCPCall(ctx, env, stack, spawner, "file_read", map[string]any{"path": "mcp_notoken.txt"}, "", true)
	return code, err
}

// ----------------------------------------------------------------------------
// E2E-39: 미지원 도구(shell_exec) 호출 차단 (ExitCode: 14)
// ----------------------------------------------------------------------------
type e2e39Scenario struct{}

func (s *e2e39Scenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID:                 "E2E-39",
		Group:              "G8",
		Name:               "미지원 도구(shell_exec) 호출 차단",
		Description:        "화이트리스트에 없는 임의 도구(shell_exec 등) 호출 시 어댑터 관문에서 자식 프로세스를 기동하지 않고 프로토콜 에러(-32602)로 즉각 거부된다.",
		AttackClass:        "ArbitraryToolExecution",
		ParadoxExplanation: "도구 화이트리스트(file_read, file_write) 외의 미인가 도구 호출은 자식 프로세스 기동 전 차단되었습니다.",
		Expected: harness.ExpectedAssertion{
			ExitCode: domain.ExitBadInput,
			File: harness.FileExpectation{
				RelPath:            "mcp_shell.txt",
				ExpectZeroMutation: true,
			},
			Audit: harness.AuditExpectation{
				RequireEvent: false, // 자식 서브프로세스 미기동
			},
			HashChain: harness.HashChainExpectation{
				RequireValidChain: true,
				NoRawTokenLeak:    true,
			},
		},
	}
}

func (s *e2e39Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return nil
}

func (s *e2e39Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	spawner, err := newMCPSpawner(env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	code, _, err := executeMCPCall(ctx, env, stack, spawner, "shell_exec", map[string]any{"cmd": "whoami"}, "dummy.jwt.token", false)
	return code, err
}
