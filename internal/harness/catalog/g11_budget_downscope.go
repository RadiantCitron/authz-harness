package catalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// G11: 예산 축소 위임 (E2E-50 ~ E2E-54)
//
// 수치는 증명하려는 검사만 걸리도록 골랐다.
//   - E2E-50: 자식 B(4)는 루트 클레임(5) 이하라 정적 검사를 통과하고, 루트 잔여(3)를 넘어 원장 검사에서만 막힌다.
//   - E2E-51: MaxCalls 를 넉넉히(5) 두어 3회차 거부 원인이 쓰기 바이트뿐이 되게 한다.
func g11Scenarios() []harness.Scenario {
	return []harness.Scenario{
		newG11E2E50(), newG11E2E51(), newG11E2E52(), newG11E2E53(), newG11E2E54(),
	}
}

// g11Scenario 는 시나리오 5건이 공유하는 얇은 골격이다.
type g11Scenario struct {
	meta  harness.ScenarioMetadata
	setup func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) error
	exec  func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) (domain.ExitCode, error)
	state g11State
}

// g11State 는 Setup 에서 Execute 로 전달되는 값이다.
type g11State struct {
	rootToken string
	rootJTI   string
}

func (s *g11Scenario) Metadata() harness.ScenarioMetadata { return s.meta }

func (s *g11Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return s.setup(ctx, env, &s.state)
}

func (s *g11Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	return s.exec(ctx, env, &s.state)
}

func g11Expect(code domain.ExitCode, relPath string, expectExist bool, action string, reason domain.Reason) harness.ExpectedAssertion {
	file := harness.FileExpectation{RelPath: relPath, ExpectZeroMutation: !expectExist, ExpectExist: expectExist}
	decision := "deny"
	if code == domain.ExitSuccess {
		decision = "allow"
	}
	return harness.ExpectedAssertion{
		ExitCode: code,
		File:     file,
		Audit: harness.AuditExpectation{
			RequireEvent: true, ExpectedAction: action, ExpectedDecision: decision, ExpectedReason: reason,
		},
		HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
	}
}

// issueBudgetRoot 는 예산 루트 토큰을 발급한다(원장 등록은 발급자가 수행).
func issueBudgetRoot(stack *harnessStack, subject, scope string, ttl time.Duration, b domain.Budget) (*token.IssueResult, error) {
	return stack.TokenIssuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: subject, Scope: scope, Audience: "authz-harness", TTL: ttl, Epoch: 1, Budget: &b,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "trace-g11-setup", Actor: "setup"})
}

func g11Exchange(ctx context.Context, svc exchange.Service, parent, sub, scope string, ttl time.Duration, b domain.Budget, trace string) (*exchange.ExchangeResult, error) {
	return svc.Exchange(ctx, exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: parent, ChildSubject: sub, Scope: scope, Audience: "authz-harness", TTL: ttl, Budget: &b,
	}, domain.AuditContext{TraceID: trace, Actor: "client-subagent", Reason: "token.exchange"})
}

func g11Remaining(stack *harnessStack, jti string) (domain.Budget, bool, error) {
	e, ok, err := stack.BudgetLedger.Get(jti)
	return e.Remaining, ok, err
}

func writeFixture(env *harness.SandboxEnvironment, rel, content string) error {
	return os.WriteFile(filepath.Join(env.WorkspaceDir, rel), []byte(content), 0o600)
}

// ----------------------------------------------------------------------------
// E2E-50: 부모 잔여 초과 위임 거부
// ----------------------------------------------------------------------------
func newG11E2E50() harness.Scenario {
	return &g11Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-50", Group: "G11", Name: "부모 잔여 초과 위임 거부",
			Description:        "루트 예산 5에서 자식 A(2)를 위임해 잔여가 3이 된 뒤, 클레임 상한(5) 이하지만 잔여(3)를 넘는 자식 B(4) 위임은 원장 검사에서 거부된다.",
			AttackClass:        "DelegationBudgetExceeded",
			ParadoxExplanation: "부모에게 남은 몫보다 많은 예산을 자식에게 나눠 주려는 시도를, 토큰이 아니라 원장의 현재 잔여로 차단했습니다.",
			Expected:           g11Expect(domain.ExitAuthzDenied, "output.txt", false, "token.exchange.deny", domain.ReasonDelegationBudgetExceeded),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) error {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return err
			}
			defer stack.Close()
			r, err := issueBudgetRoot(stack, "lead-01", "file:read", time.Hour, domain.Budget{MaxCalls: 5})
			if err != nil {
				return err
			}
			st.rootToken, st.rootJTI = r.TokenString, r.Claims.JWTID
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) (domain.ExitCode, error) {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return domain.ExitInternalError, err
			}
			defer stack.Close()

			if _, err := g11Exchange(ctx, stack.ExchangeService, st.rootToken, "worker-01", "file:read", 5*time.Minute, domain.Budget{MaxCalls: 2}, "trace-e2e-50-a"); err != nil {
				return domain.ExitInternalError, fmt.Errorf("child A exchange must succeed: %w", err)
			}
			resB, errB := g11Exchange(ctx, stack.ExchangeService, st.rootToken, "worker-02", "file:read", 5*time.Minute, domain.Budget{MaxCalls: 4}, "trace-e2e-50-b")
			if errB == nil {
				return domain.ExitSuccess, harness.Invariantf("child B (4 > remaining 3) was issued")
			}
			if resB != nil {
				return domain.ExitSuccess, harness.Invariantf("child B token returned despite denial")
			}
			if rem, ok, gerr := g11Remaining(stack, st.rootJTI); gerr != nil || !ok || rem.MaxCalls != 3 {
				return domain.ExitCodeFromError(errB, domain.ExitInternalError), harness.Invariantf("root remaining want 3, got %+v ok=%v err=%v", rem, ok, gerr)
			}
			return domain.ExitCodeFromError(errB, domain.ExitInternalError), nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-51: 쓰기 바이트 예산 소진 차단
// ----------------------------------------------------------------------------
func newG11E2E51() harness.Scenario {
	return &g11Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-51", Group: "G11", Name: "쓰기 바이트 예산 소진 차단",
			Description:        "호출 5회·쓰기 20바이트 예산으로 10바이트 쓰기 2회는 성공하고, 호출 한도가 남은 3회차(1바이트)는 바이트 예산 소진으로 거부된다.",
			AttackClass:        "BudgetExhausted",
			ParadoxExplanation: "호출 횟수는 남았지만 쓸 수 있는 바이트가 바닥나 PEP가 파일을 건드리기 전에 막았습니다.",
			Expected:           g11Expect(domain.ExitAuthzDenied, "target_blocked.txt", false, "pep.deny", domain.ReasonBudgetExhausted),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) error {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return err
			}
			defer stack.Close()
			for _, f := range []string{"target_ok.txt", "target_blocked.txt"} {
				if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, f); err != nil {
					return err
				}
			}
			r, err := issueBudgetRoot(stack, "worker-01", "file:write", 10*time.Minute, domain.Budget{MaxCalls: 5, MaxWriteBytes: 20})
			if err != nil {
				return err
			}
			st.rootToken, st.rootJTI = r.TokenString, r.Claims.JWTID
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) (domain.ExitCode, error) {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return domain.ExitInternalError, err
			}
			defer stack.Close()
			write := func(i int, file, data string) (domain.ExitCode, error) {
				return executeHarnessAction(ctx, env, stack, ActionRequest{
					Token: st.rootToken, Action: domain.ActionFileWrite, Resource: file, Data: []byte(data),
					TraceID: fmt.Sprintf("trace-e2e-51-%d", i),
				})
			}
			for i := 1; i <= 2; i++ {
				if code, err := write(i, "target_ok.txt", "0123456789"); err != nil || code != domain.ExitSuccess {
					return domain.ExitInternalError, fmt.Errorf("write #%d must succeed: code=%d err=%v", i, code, err)
				}
			}
			code, err := write(3, "target_blocked.txt", "x")
			if err != nil {
				return domain.ExitInternalError, err
			}
			if rem, ok, gerr := g11Remaining(stack, st.rootJTI); gerr != nil || !ok || rem.MaxCalls != 3 || rem.MaxWriteBytes != 0 {
				return code, harness.Invariantf("remaining want calls=3 write=0 (bytes, not calls, must be the cause), got %+v", rem)
			}
			return code, nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-52: 다중 OS 서브프로세스 동시 경합(TOCTOU) 방어
// ----------------------------------------------------------------------------
func newG11E2E52() harness.Scenario {
	const workers = 6
	s := &g11Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-52", Group: "G11", Name: "다중 서브프로세스 동시 경합 방어",
			Description:        "호출 3회 예산 토큰 하나를 워커 서브프로세스 6개가 동시에 쓰면 정확히 3개만 성공하고 3개는 거부되며, 소진된 토큰은 이후에도 거부된다.",
			AttackClass:        "BudgetTOCTOURace",
			ParadoxExplanation: "여섯 프로세스가 같은 잔량을 동시에 읽어도, 검사와 차감이 한 임계 구역이라 합계가 예산을 넘지 못했습니다.",
			RequiresSubprocess: true,
			Expected:           g11Expect(domain.ExitAuthzDenied, "contended_blocked.txt", false, "pep.deny", domain.ReasonBudgetExhausted),
		},
	}
	s.setup = func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) error {
		stack, err := setupHarnessStack(env)
		if err != nil {
			return err
		}
		defer stack.Close()
		if err := writeFixture(env, "contended_shared.txt", "shared"); err != nil {
			return err
		}
		if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileRead, "contended_shared.txt"); err != nil {
			return err
		}
		if _, err := grantPermission(ctx, stack, "worker-01", domain.ActionFileWrite, "contended_blocked.txt"); err != nil {
			return err
		}
		r, err := issueBudgetRoot(stack, "worker-01", "file:read file:write", 10*time.Minute, domain.Budget{MaxCalls: 3})
		if err != nil {
			return err
		}
		st.rootToken, st.rootJTI = r.TokenString, r.Claims.JWTID
		return nil
	}
	s.exec = func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) (domain.ExitCode, error) {
		stack, err := setupHarnessStack(env)
		if err != nil {
			return domain.ExitInternalError, err
		}
		defer stack.Close()

		codes := make([]domain.ExitCode, workers)
		errs := make([]error, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				codes[i], errs[i] = executeHarnessAction(ctx, env, stack, ActionRequest{
					Token: st.rootToken, Action: domain.ActionFileRead, Resource: "contended_shared.txt",
					TraceID: fmt.Sprintf("trace-e2e-52-w%d", i),
				})
			}(i)
		}
		wg.Wait()

		okN, deniedN := 0, 0
		for i := range codes {
			if errs[i] != nil {
				return domain.ExitInternalError, fmt.Errorf("worker %d: %w", i, errs[i])
			}
			switch codes[i] {
			case domain.ExitSuccess:
				okN++
			case domain.ExitAuthzDenied:
				deniedN++
			}
		}
		if okN != 3 || deniedN != workers-3 {
			return domain.ExitInternalError, fmt.Errorf("contention result want 3 ok / %d denied, got %d / %d (codes=%v)", workers-3, okN, deniedN, codes)
		}
		if rem, ok, gerr := g11Remaining(stack, st.rootJTI); gerr != nil || !ok || rem.MaxCalls != 0 {
			return domain.ExitInternalError, harness.Invariantf("ledger remaining want 0, got %+v ok=%v err=%v", rem, ok, gerr)
		}
		// 감사 역순 탐색이 마지막으로 pep.deny / BUDGET_EXHAUSTED 를 보도록, 소진된 같은 토큰으로 한 번 더 쓰기를 시도한다.
		return executeHarnessAction(ctx, env, stack, ActionRequest{
			Token: st.rootToken, Action: domain.ActionFileWrite, Resource: "contended_blocked.txt",
			Data: []byte("x"), TraceID: "trace-e2e-52-final",
		})
	}
	return s
}

// offsetClock 은 기준 시계에서 일정 시간 앞선 시각을 돌려주는 시계다 (E2E-53 의 "T + 120초" 스택용).
type offsetClock struct {
	base   domain.Clock
	offset time.Duration
}

func (c offsetClock) Now() time.Time { return c.base.Now().Add(c.offset) }

// ----------------------------------------------------------------------------
// E2E-53: 자식 만료 후 예약 자동 회수 및 재위임
// ----------------------------------------------------------------------------
func newG11E2E53() harness.Scenario {
	return &g11Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-53", Group: "G11", Name: "자식 만료 후 예약 자동 회수 및 재위임",
			Description:        "자식 A(4, TTL 60초)가 한 번도 쓰이지 않은 채 만료되면 다음 원장 쓰기에서 4가 부모로 회수되어, 같은 크기의 자식 B(4) 재위임과 읽기가 성공한다.",
			AttackClass:        "BudgetReclaim",
			ParadoxExplanation: "크래시한 자식이 쥐고 있던 예산이 영구 소실되지 않고, 만료 뒤 부모에게 돌아와 다시 쓰였습니다.",
			Expected:           g11Expect(domain.ExitSuccess, "reclaim.txt", true, "pep.allow", domain.ReasonAuthorized),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) error {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return err
			}
			defer stack.Close()
			if err := writeFixture(env, "reclaim.txt", "reclaimed"); err != nil {
				return err
			}
			if _, err := grantPermission(ctx, stack, "worker-02", domain.ActionFileRead, "reclaim.txt"); err != nil {
				return err
			}
			r, err := issueBudgetRoot(stack, "lead-01", "file:read", time.Hour, domain.Budget{MaxCalls: 5})
			if err != nil {
				return err
			}
			st.rootToken, st.rootJTI = r.TokenString, r.Claims.JWTID
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) (domain.ExitCode, error) {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return domain.ExitInternalError, err
			}
			defer stack.Close()

			a, err := g11Exchange(ctx, stack.ExchangeService, st.rootToken, "worker-01", "file:read", 60*time.Second, domain.Budget{MaxCalls: 4}, "trace-e2e-53-a")
			if err != nil {
				return domain.ExitInternalError, fmt.Errorf("child A exchange: %w", err)
			}
			if rem, _, _ := g11Remaining(stack, st.rootJTI); rem.MaxCalls != 1 {
				return domain.ExitInternalError, harness.Invariantf("root remaining after A want 1, got %d", rem.MaxCalls)
			}

			// 같은 파일 경로로 "T + 120초" 시계의 두 번째 스택을 조립한다 (A 는 한 번도 쓰이지 않고 만료).
			later, err := app.BuildStack(app.AppConfig{
				StatePath: env.StatePath, PrivKeyPath: env.PrivKeyPath, PubJWKSPath: env.PubJWKSPath,
				ReplayPath: env.ReplayPath, AuditPath: env.AuditPath, WorkspaceDir: env.WorkspaceDir,
				Clock: offsetClock{base: env.MockClock, offset: 120 * time.Second},
			})
			if err != nil {
				return domain.ExitInternalError, fmt.Errorf("build later stack: %w", err)
			}
			defer later.Close()

			b, err := g11Exchange(ctx, later.ExchangeService, st.rootToken, "worker-02", "file:read", 10*time.Minute, domain.Budget{MaxCalls: 4}, "trace-e2e-53-b")
			if err != nil {
				return domain.ExitInternalError, fmt.Errorf("child B exchange after reclaim: %w", err)
			}
			res, err := later.PEP.Execute(ctx, pep.Request{
				Token: b.TokenString, Action: domain.ActionFileRead, Resource: "reclaim.txt", TraceID: "trace-e2e-53-read",
			})
			if err != nil {
				return domain.ExitInternalError, err
			}

			if e, ok, gerr := later.BudgetLedger.Get(a.Claims.JWTID); gerr != nil || !ok || !e.Reclaimed {
				return res.ExitCode, harness.Invariantf("child A must be Reclaimed, got %+v ok=%v err=%v", e, ok, gerr)
			}
			if e, _, _ := later.BudgetLedger.Get(st.rootJTI); e.Remaining.MaxCalls != 1 {
				return res.ExitCode, harness.Invariantf("root remaining want 1 (1 + 4 reclaimed - 4 reserved), got %d", e.Remaining.MaxCalls)
			}
			return res.ExitCode, nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-54: 2-Hop 분할 위임 및 합계 보존
// ----------------------------------------------------------------------------
func newG11E2E54() harness.Scenario {
	return &g11Scenario{
		meta: harness.ScenarioMetadata{
			ID: "E2E-54", Group: "G11", Name: "2-Hop 분할 위임 및 합계 보존",
			Description:        "Root(5) → Lead(3) → Worker(2)로 두 번 쪼갠 뒤 Worker가 1회 읽으면, 잔여 Root=2·Lead=1·Worker=1에 소비 1을 더해 처음 5와 정확히 같다.",
			AttackClass:        "BudgetConservation",
			ParadoxExplanation: "예산이 두 단계로 나뉘어 내려가도 한 푼도 새거나 복제되지 않고 합계가 보존됐습니다.",
			Expected:           g11Expect(domain.ExitSuccess, "hop.txt", true, "pep.allow", domain.ReasonAuthorized),
		},
		setup: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) error {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return err
			}
			defer stack.Close()
			if err := writeFixture(env, "hop.txt", "hop"); err != nil {
				return err
			}
			if _, err := grantPermission(ctx, stack, "worker-02", domain.ActionFileRead, "hop.txt"); err != nil {
				return err
			}
			r, err := issueBudgetRoot(stack, "lead-01", "file:read", time.Hour, domain.Budget{MaxCalls: 5})
			if err != nil {
				return err
			}
			st.rootToken, st.rootJTI = r.TokenString, r.Claims.JWTID
			return nil
		},
		exec: func(ctx context.Context, env *harness.SandboxEnvironment, st *g11State) (domain.ExitCode, error) {
			stack, err := setupHarnessStack(env)
			if err != nil {
				return domain.ExitInternalError, err
			}
			defer stack.Close()

			lead, err := g11Exchange(ctx, stack.ExchangeService, st.rootToken, "worker-01", "file:read", 30*time.Minute, domain.Budget{MaxCalls: 3}, "trace-e2e-54-lead")
			if err != nil {
				return domain.ExitInternalError, fmt.Errorf("lead exchange: %w", err)
			}
			worker, err := g11Exchange(ctx, stack.ExchangeService, lead.TokenString, "worker-02", "file:read", 10*time.Minute, domain.Budget{MaxCalls: 2}, "trace-e2e-54-worker")
			if err != nil {
				return domain.ExitInternalError, fmt.Errorf("worker exchange: %w", err)
			}
			code, err := executeHarnessAction(ctx, env, stack, ActionRequest{
				Token: worker.TokenString, Action: domain.ActionFileRead, Resource: "hop.txt", TraceID: "trace-e2e-54-read",
			})
			if err != nil {
				return domain.ExitInternalError, err
			}

			root, _, _ := g11Remaining(stack, st.rootJTI)
			l, _, _ := g11Remaining(stack, lead.Claims.JWTID)
			w, _, _ := g11Remaining(stack, worker.Claims.JWTID)
			const consumed = 1
			if root.MaxCalls != 2 || l.MaxCalls != 1 || w.MaxCalls != 1 || root.MaxCalls+l.MaxCalls+w.MaxCalls+consumed != 5 {
				return code, harness.Invariantf("conservation broken: root=%d lead=%d worker=%d (+%d consumed) != 5", root.MaxCalls, l.MaxCalls, w.MaxCalls, consumed)
			}
			return code, nil
		},
	}
}
