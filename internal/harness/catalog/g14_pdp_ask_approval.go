package catalog

import (
	"context"
	"fmt"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G14: PDP 승인 결정(ask) (E2E-67 ~ E2E-73)
//
// 승인 필요 Grant(RequiresApproval)에 대한 쓰기가 승인 없이는 18 로 멈추고,
// 승인은 (주체, 액션, 리소스, jti, 선택적 인자 지문)에 묶인 1회용·TTL 한정이며, Grant 회수·Epoch 가 승인보다 우선함을 증명한다.
// 감사 기대는 ExpectedAction 을 pep.deny/pep.allow 로 명시해 서브프로세스 모드의 orchestrator.collect 이벤트를 건너뛴다.
func g14Scenarios() []harness.Scenario {
	return []harness.Scenario{
		newG14E2E67(), newG14E2E68(), newG14E2E69(), newG14E2E70(), newG14E2E71(), newG14E2E72(), newG14E2E73(),
	}
}

const (
	g14Subject = "worker-01"
	g14Scope   = "file:write"
)

type g14State struct {
	tokenA, jtiA string
	tokenB, jtiB string
	grantID      string
}

type g14Scenario struct {
	meta  harness.ScenarioMetadata
	setup func(ctx context.Context, stack *harnessStack, st *g14State) error
	exec  func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error)
	state g14State
}

func (s *g14Scenario) Metadata() harness.ScenarioMetadata { return s.meta }

func (s *g14Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()
	return s.setup(ctx, stack, &s.state)
}

func (s *g14Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()
	return s.exec(ctx, env, stack, &s.state)
}

func g14Expect(code domain.ExitCode, relPath string, exist bool, content, action, decision string, reason domain.Reason) harness.ExpectedAssertion {
	return harness.ExpectedAssertion{
		ExitCode: code,
		File:     harness.FileExpectation{RelPath: relPath, ExpectZeroMutation: !exist, ExpectExist: exist, ExpectedContent: content},
		Audit: harness.AuditExpectation{
			RequireEvent: true, ExpectedAction: action, ExpectedDecision: decision, ExpectedReason: reason,
		},
		HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
	}
}

// g14Token 은 worker-01 용 토큰을 발급한다(budget 이 nil 이면 일회성 토큰).
func g14Token(stack *harnessStack, ttl time.Duration, b *domain.Budget) (*token.IssueResult, error) {
	if b != nil {
		return issueBudgetRoot(stack, g14Subject, g14Scope, ttl, *b)
	}
	return stack.TokenIssuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: g14Subject, Scope: g14Scope, Audience: "authz-harness", TTL: ttl, Epoch: 1,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "trace-g14-setup", Actor: "setup"})
}

func g14Grant(ctx context.Context, stack *harnessStack, res string) (string, error) {
	g, err := stack.PAP.CreateGrant(ctx, pap.CreateGrantRequest{
		Subject: g14Subject, Action: domain.ActionFileWrite, Resource: res, RequiresApproval: true,
	})
	if err != nil {
		return "", err
	}
	return g.ID, nil
}

func g14Approve(ctx context.Context, stack *harnessStack, res, jti, argHash string, ttl time.Duration) error {
	_, err := stack.PAP.CreateApproval(ctx, pap.CreateApprovalRequest{
		Subject: g14Subject, Action: domain.ActionFileWrite, Resource: res, TokenJTI: jti, ArgHash: argHash, TTL: ttl,
	})
	return err
}

func g14Write(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, tok, res string, data []byte, offset time.Duration, trace string) (domain.ExitCode, error) {
	return executeHarnessAction(ctx, env, stack, ActionRequest{
		Token: tok, Action: domain.ActionFileWrite, Resource: res, Data: data, TraceID: trace, ClockOffset: offset,
	})
}

// g14Step 은 중간 단계의 종료 코드를 확인하고 어긋나면 Invariantf 로 시나리오를 FAIL 시킨다.
func g14Step(code domain.ExitCode, err error, want domain.ExitCode, label string) error {
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if code != want {
		return harness.Invariantf("%s: exit want %d, got %d", label, want, code)
	}
	return nil
}

func g14Approvals(stack *harnessStack) (int, error) {
	st, err := stack.StateStore.Load()
	if err != nil {
		return 0, err
	}
	return len(st.Approvals), nil
}

func g14ExpectApprovals(stack *harnessStack, want int, label string) error {
	n, err := g14Approvals(stack)
	if err != nil {
		return err
	}
	if n != want {
		return harness.Invariantf("%s: approvals in ledger want %d, got %d", label, want, n)
	}
	return nil
}

// ----------------------------------------------------------------------------
// E2E-67: 승인 필수 작업의 미승인 ask 차단
// ----------------------------------------------------------------------------
func newG14E2E67() harness.Scenario {
	const res = "g14_67.txt"
	return &g14Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-67", Group: "G14", Name: "승인 필수 작업의 미승인 ask 차단",
			Description:        "승인이 필요한 쓰기 Grant가 있어도 사람 승인이 없으면 PDP가 ask 로 판정해 18 로 끝나고, 파일은 생기지 않는다.",
			AttackClass:        "ApprovalRequired",
			ParadoxExplanation: "권한(Grant)이 있는데도 실패했습니다. 이 작업은 사람의 승인이 있어야만 실행되도록 정해져 있고, 승인이 없으면 거부와 똑같이 실패해야 정상입니다.",
			Expected:           g14Expect(domain.ExitApprovalRequired, res, false, "", "pep.deny", "ask", domain.ReasonApprovalRequired),
		},
		setup: func(ctx context.Context, stack *harnessStack, st *g14State) error {
			if _, err := g14Grant(ctx, stack, res); err != nil {
				return err
			}
			r, err := g14Token(stack, time.Hour, nil)
			if err != nil {
				return err
			}
			st.tokenA = r.TokenString
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error) {
			return g14Write(ctx, env, stack, st.tokenA, res, []byte("unapproved"), 0, "trace-e2e-67")
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-68: ask 후 승인, 같은 토큰 재시도 성공
// ----------------------------------------------------------------------------
func newG14E2E68() harness.Scenario {
	const res = "g14_68.txt"
	data := []byte("approved-retry")
	return &g14Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-68", Group: "G14", Name: "ask 후 승인, 같은 토큰 재시도 성공",
			Description:        "일회성 토큰의 1차 호출은 ask(18)로 멈추고 jti 가 소비되지 않는다. 그 jti 로 승인한 뒤 같은 토큰으로 재시도하면 성공하고 승인은 소멸한다.",
			AttackClass:        "ApprovalRetry",
			ParadoxExplanation: "한 번 막혔던 같은 토큰이 승인 뒤에는 통과합니다. 막힌 요청은 실행된 적이 없어 토큰이 소비되지 않았고, 승인은 한 번 쓰이고 사라집니다.",
			Expected:           g14Expect(domain.ExitSuccess, res, true, string(data), "pep.allow", "allow", domain.ReasonAuthorized),
		},
		setup: func(ctx context.Context, stack *harnessStack, st *g14State) error {
			if _, err := g14Grant(ctx, stack, res); err != nil {
				return err
			}
			r, err := g14Token(stack, time.Hour, nil)
			if err != nil {
				return err
			}
			st.tokenA, st.jtiA = r.TokenString, r.Claims.JWTID
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error) {
			code, err := g14Write(ctx, env, stack, st.tokenA, res, data, 0, "trace-e2e-68-ask")
			if e := g14Step(code, err, domain.ExitApprovalRequired, "first call"); e != nil {
				return code, e
			}
			if err := g14Approve(ctx, stack, res, st.jtiA, domain.DataDigest(data), 0); err != nil {
				return domain.ExitInternalError, err
			}
			code, err = g14Write(ctx, env, stack, st.tokenA, res, data, 0, "trace-e2e-68-retry")
			if err != nil {
				return code, err
			}
			if e := g14ExpectApprovals(stack, 0, "after retry"); e != nil {
				return code, e
			}
			return code, nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-69: 승인 1회 소비 후 재사용 차단
// ----------------------------------------------------------------------------
func newG14E2E69() harness.Scenario {
	const res = "g14_69.txt"
	data := []byte("first-only")
	return &g14Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-69", Group: "G14", Name: "승인 1회 소비 후 재사용 차단",
			Description:        "여러 번 쓸 수 있는 예산 토큰(MaxCalls 2)에 승인 1건을 걸면 1차 호출만 성공하고, 2차 호출은 토큰 재사용(11)이 아니라 승인 소진으로 18 에 막힌다.",
			AttackClass:        "ApprovalReuse",
			ParadoxExplanation: "토큰은 아직 두 번 쓸 수 있는데도 두 번째가 막혔습니다. 막은 것은 토큰이 아니라 승인이며, 승인은 한 번만 유효합니다.",
			Expected:           g14Expect(domain.ExitApprovalRequired, res, true, string(data), "pep.deny", "ask", domain.ReasonApprovalRequired),
		},
		setup: func(ctx context.Context, stack *harnessStack, st *g14State) error {
			if _, err := g14Grant(ctx, stack, res); err != nil {
				return err
			}
			r, err := g14Token(stack, time.Hour, &domain.Budget{MaxCalls: 2})
			if err != nil {
				return err
			}
			st.tokenA, st.jtiA = r.TokenString, r.Claims.JWTID
			return g14Approve(ctx, stack, res, st.jtiA, "", 0)
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error) {
			code, err := g14Write(ctx, env, stack, st.tokenA, res, data, 0, "trace-e2e-69-1")
			if e := g14Step(code, err, domain.ExitSuccess, "first call"); e != nil {
				return code, e
			}
			return g14Write(ctx, env, stack, st.tokenA, res, data, 0, "trace-e2e-69-2")
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-70: 다른 토큰(jti)의 승인 도용 차단
// ----------------------------------------------------------------------------
func newG14E2E70() harness.Scenario {
	const res = "g14_70.txt"
	return &g14Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-70", Group: "G14", Name: "다른 토큰(jti)의 승인 도용 차단",
			Description:        "토큰 A 의 jti 에 내준 승인은 같은 주체의 다른 토큰 B 로는 쓸 수 없다. 승인은 원장에 그대로 남는다.",
			AttackClass:        "ApprovalTheft",
			ParadoxExplanation: "같은 사람(주체)에게 내준 승인인데도 다른 토큰으로는 통하지 않습니다. 승인은 요청을 낸 그 토큰에 묶여 있기 때문입니다.",
			Expected:           g14Expect(domain.ExitApprovalRequired, res, false, "", "pep.deny", "ask", domain.ReasonApprovalMismatch),
		},
		setup: func(ctx context.Context, stack *harnessStack, st *g14State) error {
			if _, err := g14Grant(ctx, stack, res); err != nil {
				return err
			}
			a, err := g14Token(stack, time.Hour, nil)
			if err != nil {
				return err
			}
			b, err := g14Token(stack, time.Hour, nil)
			if err != nil {
				return err
			}
			st.tokenA, st.jtiA, st.tokenB, st.jtiB = a.TokenString, a.Claims.JWTID, b.TokenString, b.Claims.JWTID
			if st.jtiA == st.jtiB {
				return harness.Invariantf("token A and B must have distinct jti")
			}
			return g14Approve(ctx, stack, res, st.jtiA, "", 0)
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error) {
			code, err := g14Write(ctx, env, stack, st.tokenB, res, []byte("stolen"), 0, "trace-e2e-70")
			if err != nil {
				return code, err
			}
			return code, g14ExpectApprovals(stack, 1, "approval must stay in ledger")
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-71: 승인 후 인자 바꿔치기 차단 (Confused Deputy)
// ----------------------------------------------------------------------------
func newG14E2E71() harness.Scenario {
	const res = "g14_71.txt"
	return &g14Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-71", Group: "G14", Name: "승인 후 인자 바꿔치기 차단",
			Description:        "\"approved\" 내용의 지문에 묶어 승인했는데 같은 토큰으로 \"tampered\" 내용을 쓰려 하면 지문이 달라 18 에 막힌다.",
			AttackClass:        "ConfusedDeputy",
			ParadoxExplanation: "사람은 특정 내용을 쓰는 것을 승인했습니다. 내용을 몰래 바꾼 요청은 같은 토큰·같은 파일이어도 승인 범위 밖이라 실행되지 않습니다.",
			Expected:           g14Expect(domain.ExitApprovalRequired, res, false, "", "pep.deny", "ask", domain.ReasonApprovalMismatch),
		},
		setup: func(ctx context.Context, stack *harnessStack, st *g14State) error {
			if _, err := g14Grant(ctx, stack, res); err != nil {
				return err
			}
			r, err := g14Token(stack, time.Hour, nil)
			if err != nil {
				return err
			}
			st.tokenA, st.jtiA = r.TokenString, r.Claims.JWTID
			return g14Approve(ctx, stack, res, st.jtiA, domain.DataDigest([]byte("approved")), 0)
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error) {
			code, err := g14Write(ctx, env, stack, st.tokenA, res, []byte("tampered"), 0, "trace-e2e-71")
			if err != nil {
				return code, err
			}
			return code, g14ExpectApprovals(stack, 1, "approval must stay in ledger")
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-72: TTL 만료 승인 차단
// ----------------------------------------------------------------------------
func newG14E2E72() harness.Scenario {
	const res = "g14_72.txt"
	return &g14Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-72", Group: "G14", Name: "TTL 만료 승인 차단",
			Description:        "TTL 1분 승인을 가상 시계 +2분 시점에 쓰려 하면 토큰(TTL 10분)은 유효해도 승인이 만료되어 18 에 막힌다.",
			AttackClass:        "ApprovalExpired",
			ParadoxExplanation: "토큰은 아직 살아 있지만 승인은 이미 죽었습니다. 승인 만료는 요청 시각(가상 시계 반영)으로 판정합니다.",
			Expected:           g14Expect(domain.ExitApprovalRequired, res, false, "", "pep.deny", "ask", domain.ReasonApprovalExpired),
		},
		setup: func(ctx context.Context, stack *harnessStack, st *g14State) error {
			if _, err := g14Grant(ctx, stack, res); err != nil {
				return err
			}
			r, err := g14Token(stack, 10*time.Minute, nil)
			if err != nil {
				return err
			}
			st.tokenA, st.jtiA = r.TokenString, r.Claims.JWTID
			return g14Approve(ctx, stack, res, st.jtiA, "", time.Minute)
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error) {
			return g14Write(ctx, env, stack, st.tokenA, res, []byte("late"), 2*time.Minute, "trace-e2e-72")
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-73: 승인 후 Grant 회수 시 승인 우회 차단
// ----------------------------------------------------------------------------
func newG14E2E73() harness.Scenario {
	const res = "g14_73.txt"
	return &g14Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-73", Group: "G14", Name: "승인 후 Grant 회수 시 승인 우회 차단",
			Description:        "유효한 승인을 받은 뒤 Grant 가 회수되면 승인이 남아 있어도 PDP 가 GRANT_REVOKED(12)로 거부한다. 승인은 권한을 대체하지 못한다.",
			AttackClass:        "ApprovalBypassRevoked",
			ParadoxExplanation: "사람이 승인했는데도 막혔습니다. 승인은 권한 위에 얹는 추가 조건일 뿐이라, 권한이 회수되면 승인은 아무 힘이 없습니다.",
			Expected:           g14Expect(domain.ExitAuthzDenied, res, false, "", "pep.deny", "deny", domain.ReasonGrantRevoked),
		},
		setup: func(ctx context.Context, stack *harnessStack, st *g14State) error {
			gid, err := g14Grant(ctx, stack, res)
			if err != nil {
				return err
			}
			st.grantID = gid
			r, err := g14Token(stack, time.Hour, nil)
			if err != nil {
				return err
			}
			st.tokenA, st.jtiA = r.TokenString, r.Claims.JWTID
			return g14Approve(ctx, stack, res, st.jtiA, "", 0)
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, st *g14State) (domain.ExitCode, error) {
			if _, err := stack.PAP.RevokeGrant(ctx, st.grantID); err != nil {
				return domain.ExitInternalError, err
			}
			return g14Write(ctx, env, stack, st.tokenA, res, []byte("revoked"), 0, "trace-e2e-73")
		},
	}
}
