package catalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G12: 장기 실행 및 토큰 수명 검증 (E2E-55 ~ E2E-60)
//
// 하나의 MCP 세션(SessionDriver) 안에서 연속 호출 도중 만료·계보 회수·키 폐기·재사용·재교환이 일어난다.
// 중간 단계 기대값이 어긋나면 Invariantf 로 시나리오를 FAIL 시킨다(실행 결과에 기대값을 맞추지 않는다).
// 시간은 SessionDriver.AdvanceClock 으로만 흐르며 실제 대기는 하지 않는다.
func g12Scenarios() []harness.Scenario {
	return []harness.Scenario{
		newG12E2E55(), newG12E2E56(), newG12E2E57(), newG12E2E58(), newG12E2E59(), newG12E2E60(),
	}
}

const g12Scope = "file:read file:write"

type g12State struct {
	token  string // 세션 호출에 쓰는 기본 토큰
	parent string // 재교환 시나리오의 부모 토큰
	kid    string // 서명 키 ID
}

type g12Scenario struct {
	meta  harness.ScenarioMetadata
	setup func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g12State) error
	exec  func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error)
	state g12State
}

func (s *g12Scenario) Metadata() harness.ScenarioMetadata { return s.meta }

func (s *g12Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()
	if err := writeFixture(env, "g12_read.txt", "g12"); err != nil {
		return err
	}
	for _, g := range []struct {
		a domain.Action
		r string
	}{{domain.ActionFileRead, "g12_read.txt"}, {domain.ActionFileWrite, "g12_write.txt"}} {
		if _, err := grantPermission(ctx, stack, "worker-01", g.a, g.r); err != nil {
			return err
		}
	}
	return s.setup(ctx, env, stack, &s.state)
}

func (s *g12Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()
	d, err := NewSessionDriver(ctx, env, stack)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer d.Close()
	return s.exec(ctx, env, d, &s.state)
}

func g12Expect(code domain.ExitCode, relPath string, exist bool, action string, reason domain.Reason) harness.ExpectedAssertion {
	decision := "deny"
	if code == domain.ExitSuccess {
		decision = "allow"
	}
	return harness.ExpectedAssertion{
		ExitCode: code,
		File:     harness.FileExpectation{RelPath: relPath, ExpectZeroMutation: !exist, ExpectExist: exist},
		Audit: harness.AuditExpectation{
			RequireEvent: true, ExpectedAction: action, ExpectedDecision: decision, ExpectedReason: reason,
		},
		HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
	}
}

// g12Call 은 세션 호출 1건을 실행하고 중간 기대 종료 코드를 확인한다(want < 0 이면 확인 생략하고 코드만 반환).
func g12Call(d *SessionDriver, tool string, args map[string]any, tok string, want domain.ExitCode, label string) (domain.ExitCode, error) {
	code, _, err := d.CallTool(tool, args, tok)
	if err != nil {
		return domain.ExitInternalError, fmt.Errorf("%s: %w", label, err)
	}
	if code != want {
		return code, harness.Invariantf("%s: exit want %d, got %d", label, want, code)
	}
	return code, nil
}

var (
	g12Read  = map[string]any{"path": "g12_read.txt"}
	g12Write = map[string]any{"path": "g12_write.txt", "data": "g12-written"}
)

func g12BudgetRoot(stack *harnessStack, subject string, ttl time.Duration, calls int64) (*token.IssueResult, error) {
	return issueBudgetRoot(stack, subject, g12Scope, ttl, domain.Budget{MaxCalls: calls})
}

func g12Root(stack *harnessStack, subject string, ttl time.Duration) (*token.IssueResult, error) {
	return stack.TokenIssuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: subject, Scope: g12Scope, Audience: "authz-harness", TTL: ttl, Epoch: 1,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "trace-g12-setup", Actor: "setup"})
}

// exchangeReq 는 client-subagent 가 worker-01 에게 위임하는 표준 교환 요청이다(ChildEpoch 1).
func exchangeReq(parent string, ttl time.Duration) exchange.ExchangeRequest {
	return exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: parent, ChildSubject: "worker-01", Scope: g12Scope,
		Audience: "authz-harness", TTL: ttl, ChildEpoch: 1,
	}
}

// g12Child 는 부모 토큰에서 worker-01 자식 토큰을 교환한다(예산 없음, ChildEpoch 1).
func g12Child(ctx context.Context, stack *harnessStack, parent string, ttl time.Duration, trace string) (string, error) {
	r, err := stack.ExchangeService.Exchange(ctx, exchangeReq(parent, ttl), domain.AuditContext{TraceID: trace, Actor: "client-subagent", Reason: "token.exchange"})
	if err != nil {
		return "", err
	}
	return r.TokenString, nil
}

// ----------------------------------------------------------------------------
// E2E-55: 세션 중 토큰 시간 만료 차단
// ----------------------------------------------------------------------------
func newG12E2E55() harness.Scenario {
	return &g12Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-55", Group: "G12", Name: "세션 중 토큰 시간 만료 차단",
			Description:        "같은 MCP 세션에서 예산 토큰(TTL 5분)으로 읽기에 성공한 뒤 시계를 10분 전진시키면, 같은 토큰의 쓰기 호출은 만료로 거부된다.",
			AttackClass:        "SessionTokenExpiry",
			ParadoxExplanation: "세션이 열려 있어도 토큰의 수명은 호출마다 다시 검사되어, 시간이 지나면 같은 토큰이 즉시 무력화됩니다.",
			Expected:           g12Expect(domain.ExitTokenInvalid, "g12_write.txt", false, "pep.deny", domain.ReasonTokenExpired),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g12State) error {
			r, err := g12BudgetRoot(stack, "worker-01", 5*time.Minute, 5)
			if err != nil {
				return err
			}
			st.token = r.TokenString
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitSuccess, "call1"); err != nil {
				return domain.ExitInternalError, err
			}
			if err := d.AdvanceClock(10 * time.Minute); err != nil {
				return domain.ExitInternalError, err
			}
			code, _, err := d.CallTool("file_write", g12Write, st.token)
			return code, err
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-56: 상위 위임자 Epoch 증가로 하위 토큰 연쇄 차단
// ----------------------------------------------------------------------------
func newG12E2E56() harness.Scenario {
	return &g12Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-56", Group: "G12", Name: "상위 위임자 Epoch 증가로 하위 토큰 연쇄 차단",
			Description:        "lead-01 이 위임한 worker-01 토큰으로 읽기에 성공한 뒤, 자식이 아닌 상위 lead-01 의 Epoch 만 올리면 같은 세션의 자식 토큰 쓰기가 거부된다.",
			AttackClass:        "LineageRevocation",
			ParadoxExplanation: "자식 토큰은 아무것도 바뀌지 않았지만, 위임 계보의 조상 하나가 회수되자 파생 토큰 전체가 함께 무효화되었습니다.",
			Expected:           g12Expect(domain.ExitAuthzDenied, "g12_write.txt", false, "pep.deny", domain.ReasonSubjectEpochRevoked),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g12State) error {
			root, err := g12BudgetRoot(stack, "lead-01", 10*time.Minute, 5)
			if err != nil {
				return err
			}
			b := domain.Budget{MaxCalls: 3}
			req := exchangeReq(root.TokenString, 5*time.Minute)
			req.Budget = &b
			c, err := stack.ExchangeService.Exchange(ctx, req, domain.AuditContext{TraceID: "trace-g12-56-x", Actor: "client-subagent", Reason: "token.exchange"})
			if err != nil {
				return err
			}
			st.token = c.TokenString
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitSuccess, "call1"); err != nil {
				return domain.ExitInternalError, err
			}
			if _, err := d.BumpEpoch(ctx, "lead-01"); err != nil {
				return domain.ExitInternalError, err
			}
			code, _, err := d.CallTool("file_write", g12Write, st.token)
			return code, err
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-57: 서명 키 회전(유지) 후 폐기 즉시 차단
// ----------------------------------------------------------------------------
func newG12E2E57() harness.Scenario {
	return &g12Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-57", Group: "G12", Name: "서명 키 회전(유지) 후 폐기 즉시 차단",
			Description:        "키를 회전해도 이전 키는 검증 전용으로 남아 같은 토큰이 계속 통과하지만, 이전 키를 폐기하면 같은 세션의 다음 호출이 즉시 거부된다.",
			AttackClass:        "KeyRetirement",
			ParadoxExplanation: "회전은 기존 토큰을 살려 두고 폐기만이 즉시 끊는다는 구분을, 같은 토큰의 세 번의 호출로 보였습니다.",
			Expected:           g12Expect(domain.ExitTokenInvalid, "g12_write.txt", false, "pep.deny", domain.ReasonTokenKeyRetired),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g12State) error {
			r, err := g12BudgetRoot(stack, "worker-01", 10*time.Minute, 5)
			if err != nil {
				return err
			}
			st.token, st.kid = r.TokenString, r.KeyID
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitSuccess, "call1"); err != nil {
				return domain.ExitInternalError, err
			}
			if err := d.RotateKey(); err != nil {
				return domain.ExitInternalError, err
			}
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitSuccess, "call2(after rotate)"); err != nil {
				return domain.ExitInternalError, err
			}
			if err := d.RevokeKey(st.kid); err != nil {
				return domain.ExitInternalError, err
			}
			code, _, err := d.CallTool("file_write", g12Write, st.token)
			return code, err
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-58: 세션 내 일회성 토큰 2회차 재사용 차단
// ----------------------------------------------------------------------------
func newG12E2E58() harness.Scenario {
	return &g12Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-58", Group: "G12", Name: "세션 내 일회성 토큰 2회차 재사용 차단",
			Description:        "예산이 없는 일회성 토큰은 한 세션에서 첫 호출만 통과하고 같은 토큰의 두 번째 호출은 Replay 로 거부된다.",
			AttackClass:        "SessionTokenReplay",
			ParadoxExplanation: "세션을 계속 열어 두어도 일회성 토큰의 jti 는 한 번 쓰이면 소진되어 다시 쓸 수 없습니다.",
			Expected:           g12Expect(domain.ExitTokenInvalid, "g12_write.txt", false, "pep.deny", domain.ReasonTokenReplayDetected),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g12State) error {
			r, err := g12Root(stack, "worker-01", 10*time.Minute)
			if err != nil {
				return err
			}
			st.token = r.TokenString
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitSuccess, "call1"); err != nil {
				return domain.ExitInternalError, err
			}
			code, _, err := d.CallTool("file_write", g12Write, st.token)
			return code, err
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-59: 자식 만료 후 유효 부모로 재교환해 세션 재개
// ----------------------------------------------------------------------------
func newG12E2E59() harness.Scenario {
	return &g12Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-59", Group: "G12", Name: "자식 만료 후 유효 부모로 재교환해 세션 재개",
			Description:        "자식 토큰(TTL 5분)이 만료돼 거부되어도, 아직 유효한 부모 토큰으로 다시 교환한 새 자식 토큰으로 같은 세션이 작업을 재개한다. Refresh Token 은 쓰지 않는다.",
			AttackClass:        "ReExchange",
			ParadoxExplanation: "장기 세션은 만료된 토큰을 연장하는 대신, 부모의 남은 수명 안에서 새 자식을 다시 위임받는 방식으로 이어집니다.",
			Expected:           g12Expect(domain.ExitSuccess, "g12_write.txt", true, "pep.allow", domain.ReasonAuthorized),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g12State) error {
			p, err := g12Root(stack, "lead-01", 30*time.Minute)
			if err != nil {
				return err
			}
			c, err := g12Child(ctx, stack, p.TokenString, 5*time.Minute, "trace-g12-59-1")
			if err != nil {
				return err
			}
			st.parent, st.token = p.TokenString, c
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitSuccess, "call1"); err != nil {
				return domain.ExitInternalError, err
			}
			if err := d.AdvanceClock(6 * time.Minute); err != nil {
				return domain.ExitInternalError, err
			}
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitTokenInvalid, "call2(expired child)"); err != nil {
				return domain.ExitInternalError, err
			}
			off, err := d.Stack()
			if err != nil {
				return domain.ExitInternalError, err
			}
			c2, err := g12Child(ctx, off, st.parent, 5*time.Minute, "trace-g12-59-2")
			if err != nil {
				return domain.ExitInternalError, fmt.Errorf("re-exchange must succeed: %w", err)
			}
			code, _, err := d.CallTool("file_write", g12Write, c2)
			if err == nil && code == domain.ExitSuccess {
				b, rerr := os.ReadFile(filepath.Join(env.WorkspaceDir, "g12_write.txt"))
				if rerr != nil || string(b) != "g12-written" {
					return code, harness.Invariantf("written content mismatch: %q err=%v", b, rerr)
				}
			}
			return code, err
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-60: 부모 만료 후 재교환 거부
// ----------------------------------------------------------------------------
func newG12E2E60() harness.Scenario {
	return &g12Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-60", Group: "G12", Name: "부모 만료 후 재교환 거부 (수명 상한 우회 차단)",
			Description:        "부모 토큰(TTL 10분)까지 만료된 뒤에는 재교환이 거부되어, 자식을 반복 교환해도 부모의 수명 상한을 넘겨 살아남을 수 없다.",
			AttackClass:        "ReExchangeParentExpired",
			ParadoxExplanation: "재교환은 부모가 살아 있는 동안만 가능해서, 위임 사슬 전체의 수명이 가장 짧은 조상에 묶입니다.",
			Expected:           g12Expect(domain.ExitTokenInvalid, "g12_new.txt", false, "token.exchange.deny", domain.ReasonTokenExpired),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g12State) error {
			p, err := g12Root(stack, "lead-01", 10*time.Minute)
			if err != nil {
				return err
			}
			c, err := g12Child(ctx, stack, p.TokenString, 5*time.Minute, "trace-g12-60-1")
			if err != nil {
				return err
			}
			st.parent, st.token = p.TokenString, c
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
			if _, err := g12Call(d, "file_read", g12Read, st.token, domain.ExitSuccess, "call1"); err != nil {
				return domain.ExitInternalError, err
			}
			if err := d.AdvanceClock(15 * time.Minute); err != nil {
				return domain.ExitInternalError, err
			}
			off, err := d.Stack()
			if err != nil {
				return domain.ExitInternalError, err
			}
			res, xerr := g12Child(ctx, off, st.parent, 5*time.Minute, "trace-g12-60-2")
			if xerr == nil {
				return domain.ExitSuccess, harness.Invariantf("re-exchange with expired parent succeeded (token len %d)", len(res))
			}
			return domain.ExitCodeFromError(xerr, domain.ExitInternalError), nil
		},
	}
}
