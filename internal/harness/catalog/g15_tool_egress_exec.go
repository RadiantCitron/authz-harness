package catalog

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// G15: 도구 종류 확장과 egress 통제 (E2E-74 ~ E2E-79)
//
// net:fetch(루프백 전용 GET)와 exec:run(코드 고정 allow-list)이 실제 워커 바이너리 경로에서 정상 동작하고,
// 표기 우회·리다이렉트·인자 주입·자원 폭주·PEP 우회가 막힘을 증명한다.
// 판정은 종료 코드 + 감사 이벤트 + 부모가 관찰한 사실(서버 요청 수·리스너 accept 수·출력)로만 내린다.
func g15Scenarios() []harness.Scenario {
	return withStages([]harness.Scenario{
		newG15E2E74(), newG15E2E75(), newG15E2E76(), newG15E2E77(), newG15E2E78(), newG15E2E79(),
	})
}

const g15Subject = "worker-01"

// g15Server 는 요청 수를 세는 루프백 시험 서버다.
type g15Server struct {
	srv  *httptest.Server
	Host string // "127.0.0.1:<port>"
	Port int
	hits atomic.Int32
}

func newG15Server(handler func(w http.ResponseWriter, r *http.Request)) *g15Server {
	s := &g15Server{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		handler(w, r)
	}))
	u, _ := url.Parse(s.srv.URL)
	s.Host = u.Host
	s.Port, _ = strconv.Atoi(u.Port())
	return s
}

func (s *g15Server) Close()      { s.srv.Close() }
func (s *g15Server) Hits() int32 { return s.hits.Load() }

func g15Body(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }
}

// g15Grant 는 Grant 를 만들고 같은 3단 스코프의 새 토큰을 발급한다(시도마다 새 토큰: jti 는 allow 뒤 소비된다).
func g15Grant(ctx context.Context, stack *harnessStack, action domain.Action, resource string) error {
	_, err := grantPermission(ctx, stack, g15Subject, action, resource)
	return err
}

func g15Token(stack *harnessStack, scope string) (string, error) {
	return issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01", g15Subject, scope, time.Hour, token.IssueOptions{})
}

type g15Spawn struct {
	netAllow []string
	limits   orchestrator.Limits
	confiner confinement.Confiner
	policy   confinement.Policy
}

func g15SpawnWorker(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, sc g15Spawn, req subagent.SubagentRequest) (*orchestrator.SpawnResult, error) {
	limits := sc.limits
	if limits == (orchestrator.Limits{}) {
		limits = orchestrator.DefaultLimits()
	}
	sp, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath:  env.BinaryPath,
		Args:        orchestrator.WorkerArgs(env.WorkspaceDir, env.StatePath, env.PubJWKSPath, env.ReplayPath, env.AuditPath, strings.Join(sc.netAllow, ","), false),
		Limits:      limits,
		Audit:       stack.AuditWriter,
		Confiner:    sc.confiner,
		Confinement: sc.policy,
	})
	if err != nil {
		return nil, err
	}
	req.Version = "1.0"
	return sp.Spawn(ctx, req)
}

// g15LastEvent 는 trace 의 마지막 (action) 이벤트를 찾는다. stage 가 비어 있지 않으면 metadata.stage 도 맞아야 한다.
func g15LastEvent(env *harness.SandboxEnvironment, trace, action, stage string) (audit.Event, bool, error) {
	events, err := env.ReadAuditEvents()
	if err != nil {
		return audit.Event{}, false, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		if ev.TraceID != trace || ev.Action != action {
			continue
		}
		if stage != "" {
			if ev.Stage != stage {
				continue
			}
		}
		return ev, true, nil
	}
	return audit.Event{}, false, nil
}

// g15ExpectDeny 는 중간 시도가 (종료 코드, 감사 사유) 로 거부되었는지 확인한다.
func g15ExpectDeny(env *harness.SandboxEnvironment, res *orchestrator.SpawnResult, trace string, code domain.ExitCode, reason domain.Reason, label string) error {
	if domain.ExitCode(res.ExitCode) != code {
		return harness.Invariantf("%s: exit want %d, got %d", label, code, res.ExitCode)
	}
	ev, ok, err := g15LastEvent(env, trace, "pep.deny", "")
	if err != nil {
		return err
	}
	if !ok || ev.Reason != string(reason) {
		return harness.Invariantf("%s: audit reason want %s, got %q (found=%v)", label, reason, ev.Reason, ok)
	}
	return nil
}

func g15Expect(code domain.ExitCode, action, decision string, reason domain.Reason, trace string) harness.ExpectedAssertion {
	return harness.ExpectedAssertion{
		ExitCode: code,
		Audit: harness.AuditExpectation{
			RequireEvent: true, ExpectedAction: action, ExpectedDecision: decision, ExpectedReason: reason, ExpectedTraceID: trace,
		},
		HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
	}
}

type g15Scenario struct {
	meta harness.ScenarioMetadata
	run  func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, mut string) (domain.ExitCode, error)
	mut  string // 변이 검증(TC-060-02)에서만 쓰는 주입점
}

func (s *g15Scenario) Metadata() harness.ScenarioMetadata { return s.meta }

func (s *g15Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return precreateAuditLock(env)
}

func (s *g15Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()
	return s.run(ctx, env, stack, s.mut)
}

func g15Meta(id, name, desc, attack, paradox string, confined bool, exp harness.ExpectedAssertion) harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID: id, Group: "G15", Name: name, Description: desc, AttackClass: attack, ParadoxExplanation: paradox,
		RequiresSubprocess: true, RequiresConfinement: confined, Expected: exp,
	}
}

// ----------------------------------------------------------------------------
// E2E-74: 루프백 allow-list net:fetch 정상 실행
// ----------------------------------------------------------------------------
func newG15E2E74() harness.Scenario {
	const trace = "trace-e2e-74"
	return &g15Scenario{
		meta: g15Meta("E2E-74", "루프백 allow-list net:fetch 정상 실행",
			"allow-list 에 있는 루프백 포트로의 GET 이 워커 경로에서 성공하고, 감사에는 정규화된 host:port 와 지문만 남는다.",
			"None", "허용된 도구는 막히지 않으며, 감사에는 URL 원문이 아니라 host:port 와 SHA-256 지문만 남습니다.", false,
			g15Expect(domain.ExitSuccess, "pep.allow", "allow", domain.ReasonAuthorized, trace)),
		run: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, mut string) (domain.ExitCode, error) {
			srv := newG15Server(g15Body("status-ok"))
			defer srv.Close()
			if err := g15Grant(ctx, stack, domain.ActionNetFetch, srv.Host); err != nil {
				return domain.ExitInternalError, err
			}
			tok, err := g15Token(stack, "net:fetch:"+srv.Host)
			if err != nil {
				return domain.ExitInternalError, err
			}
			target := "http://" + srv.Host + "/status"
			res, err := g15SpawnWorker(ctx, env, stack, g15Spawn{netAllow: []string{srv.Host}},
				subagent.SubagentRequest{TraceID: trace, Token: tok, Action: string(domain.ActionNetFetch), FilePath: target})
			if err != nil {
				return domain.ExitInternalError, err
			}
			code := domain.ExitCode(res.ExitCode)
			if code != domain.ExitSuccess {
				return code, nil
			}
			if srv.Hits() != 1 {
				return code, harness.Invariantf("server hits want 1, got %d", srv.Hits())
			}
			ev, ok, err := g15LastEvent(env, trace, "pep.allow", string(domain.StageExecute))
			if err != nil {
				return code, err
			}
			wantResult := domain.DataDigest([]byte("status-ok"))
			if mut == "bad-result-hash" {
				wantResult = domain.DataDigest([]byte("tampered"))
			}
			if !ok || ev.Resource != srv.Host || ev.ArgHash != domain.DataDigest([]byte(target)) || ev.ResultHash != wantResult {
				return code, harness.Invariantf("audit mismatch: found=%v resource=%q arg_hash=%q result_hash=%q", ok, ev.Resource, ev.ArgHash, ev.ResultHash)
			}
			return code, nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-75: 표기 우회와 비허용 포트 차단
// ----------------------------------------------------------------------------
func newG15E2E75() harness.Scenario {
	const trace = "trace-e2e-75-d"
	return &g15Scenario{
		meta: g15Meta("E2E-75", "표기 우회와 비허용 포트 차단",
			"userinfo·정수 IP·localhost 표기와, Grant 가 있어도 코드 측 allow-list 밖인 포트가 모두 EGRESS_DENIED 로 막힌다.",
			"EgressBypass", "URL 표기를 바꿔도, Grant 가 있어도, 코드에 적힌 allow-list 밖으로는 나가지 못합니다. 서버는 한 번도 호출되지 않았습니다.", false,
			g15Expect(domain.ExitAuthzDenied, "pep.deny", "deny", domain.ReasonEgressDenied, trace)),
		run: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, mut string) (domain.ExitCode, error) {
			p := newG15Server(g15Body("p"))
			defer p.Close()
			q := newG15Server(g15Body("q"))
			defer q.Close()
			if err := g15Grant(ctx, stack, domain.ActionNetFetch, q.Host); err != nil {
				return domain.ExitInternalError, err
			}
			allow := []string{p.Host}
			if mut == "allow-q" {
				allow = append(allow, q.Host)
			}
			attempts := []struct{ suffix, url string }{
				{"a", "http://" + p.Host + "@evil/"},
				{"b", "http://2130706433:" + strconv.Itoa(p.Port) + "/"},
				{"c", "http://localhost:" + strconv.Itoa(p.Port) + "/"},
				{"d", "http://" + q.Host + "/"},
			}
			var last domain.ExitCode
			for _, a := range attempts {
				tok, err := g15Token(stack, "net:fetch:"+q.Host)
				if err != nil {
					return domain.ExitInternalError, err
				}
				tr := "trace-e2e-75-" + a.suffix
				res, err := g15SpawnWorker(ctx, env, stack, g15Spawn{netAllow: allow},
					subagent.SubagentRequest{TraceID: tr, Token: tok, Action: string(domain.ActionNetFetch), FilePath: a.url})
				if err != nil {
					return domain.ExitInternalError, err
				}
				last = domain.ExitCode(res.ExitCode)
				if a.suffix != "d" {
					if err := g15ExpectDeny(env, res, tr, domain.ExitAuthzDenied, domain.ReasonEgressDenied, "attempt "+a.suffix); err != nil {
						return last, err
					}
				}
			}
			if p.Hits() != 0 || q.Hits() != 0 {
				return last, harness.Invariantf("servers must not be contacted: P=%d Q=%d", p.Hits(), q.Hits())
			}
			raw, err := os.ReadFile(env.AuditPath)
			if err != nil {
				return last, err
			}
			if bytes.Contains(raw, []byte("evil")) {
				return last, harness.Invariantf("raw URL fragment %q leaked into audit", "evil")
			}
			return last, nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-76: 리다이렉트 차단
// ----------------------------------------------------------------------------
func newG15E2E76() harness.Scenario {
	const trace = "trace-e2e-76"
	return &g15Scenario{
		meta: g15Meta("E2E-76", "리다이렉트 차단",
			"allow-list 서버가 다른 루프백 서버로 302 를 보내도 따라가지 않고 EGRESS_DENIED 로 거부한다.",
			"EgressBypass", "검사한 주소와 실제로 연결하는 주소가 같아야 합니다. 리다이렉트는 검사하지 않은 주소이므로 따라가지 않았습니다.", false,
			g15Expect(domain.ExitAuthzDenied, "pep.deny", "deny", domain.ReasonEgressDenied, trace)),
		run: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, mut string) (domain.ExitCode, error) {
			r := newG15Server(g15Body("REDIRECTED-SECRET-BODY"))
			defer r.Close()
			p := newG15Server(func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, "http://"+r.Host+"/", http.StatusFound)
			})
			defer p.Close()
			if err := g15Grant(ctx, stack, domain.ActionNetFetch, p.Host); err != nil {
				return domain.ExitInternalError, err
			}
			tok, err := g15Token(stack, "net:fetch:"+p.Host)
			if err != nil {
				return domain.ExitInternalError, err
			}
			res, err := g15SpawnWorker(ctx, env, stack, g15Spawn{netAllow: []string{p.Host}},
				subagent.SubagentRequest{TraceID: trace, Token: tok, Action: string(domain.ActionNetFetch), FilePath: "http://" + p.Host + "/"})
			if err != nil {
				return domain.ExitInternalError, err
			}
			code := domain.ExitCode(res.ExitCode)
			if p.Hits() < 1 {
				return code, harness.Invariantf("origin server was never contacted: 시험이 가짜일 수 있음")
			}
			if r.Hits() != 0 {
				return code, harness.Invariantf("redirect target contacted %d times", r.Hits())
			}
			if strings.Contains(res.StdoutRaw, "REDIRECTED-SECRET-BODY") {
				return code, harness.Invariantf("redirect body leaked to worker output")
			}
			return code, nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-77: exec:run 정상 실행 뒤 주입·미등록 ID 차단
// ----------------------------------------------------------------------------
func newG15E2E77() harness.Scenario {
	const trace = "trace-e2e-77-c"
	return &g15Scenario{
		meta: g15Meta("E2E-77", "exec:run 정상 실행 뒤 주입·미등록 ID 차단",
			"등록된 echo-safe 는 실행되지만, 메타문자 인자와 미등록 ID(sh)는 Grant 가 있어도 막히고 워크스페이스는 바뀌지 않는다.",
			"ExecInjection", "허용된 실행 ID 만 셸 없이, 빈 환경으로 실행됩니다. 인자에 명령을 끼워 넣거나 다른 실행 파일을 지정해도 실행되지 않았습니다.", false,
			g15Expect(domain.ExitAuthzDenied, "pep.deny", "deny", domain.ReasonExecNotAllowed, trace)),
		run: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, mut string) (domain.ExitCode, error) {
			for _, id := range []string{"echo-safe", "sh"} {
				if err := g15Grant(ctx, stack, domain.ActionExecRun, id); err != nil {
					return domain.ExitInternalError, err
				}
			}
			scope := "exec:run:echo-safe exec:run:sh"
			before, err := g15WorkspaceListing(env)
			if err != nil {
				return domain.ExitInternalError, err
			}
			step := func(suffix, id, arg string) (*orchestrator.SpawnResult, error) {
				tok, err := g15Token(stack, scope)
				if err != nil {
					return nil, err
				}
				return g15SpawnWorker(ctx, env, stack, g15Spawn{},
					subagent.SubagentRequest{TraceID: "trace-e2e-77-" + suffix, Token: tok, Action: string(domain.ActionExecRun), FilePath: id, Data: arg})
			}
			// 대조: 정책이 너무 좁아 모두 막히는 가짜 차단 배제
			a, err := step("a", "echo-safe", "hello_123")
			if err != nil {
				return domain.ExitInternalError, err
			}
			if a.ExitCode != 0 || a.Response == nil || a.Response.Output != "hello_123\n" {
				return domain.ExitInternalError, harness.Invariantf("control exec: exit=%d, output mismatch", a.ExitCode)
			}
			b, err := step("b", "echo-safe", "a;touch_pwned")
			if err != nil {
				return domain.ExitInternalError, err
			}
			if err := g15ExpectDeny(env, b, "trace-e2e-77-b", domain.ExitAuthzDenied, domain.ReasonExecArgRejected, "injection"); err != nil {
				return domain.ExitCode(b.ExitCode), err
			}
			c, err := step("c", "sh", "")
			if err != nil {
				return domain.ExitInternalError, err
			}
			after, err := g15WorkspaceListing(env)
			if err != nil {
				return domain.ExitCode(c.ExitCode), err
			}
			if before != after {
				return domain.ExitCode(c.ExitCode), harness.Invariantf("workspace changed: %q -> %q", before, after)
			}
			return domain.ExitCode(c.ExitCode), nil
		},
	}
}

func g15WorkspaceListing(env *harness.SandboxEnvironment) (string, error) {
	entries, err := os.ReadDir(env.WorkspaceDir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, ","), nil
}

// ----------------------------------------------------------------------------
// E2E-78: 부모 출력 상한이 새 도구에도 걸림
// ----------------------------------------------------------------------------
func newG15E2E78() harness.Scenario {
	const trace = "trace-e2e-78"
	const parentLimit = 16 << 10
	return &g15Scenario{
		meta: g15Meta("E2E-78", "부모 출력 상한이 새 도구에도 걸림",
			"가드 기본 상한(1 MiB)보다 작은 부모 출력 상한이 net:fetch 에도 적용되어 17 로 끝난다.",
			"ResourceExhaustion", "도구가 아무리 큰 응답을 받아 와도, 부모가 정한 출력 한계를 넘으면 부모가 워커를 끝냅니다. 가드 상한(12)이 아니라 부모 상한(17)이 먼저 걸렸습니다.", false,
			g15Expect(domain.ExitResourceLimit, orchestrator.AuditActionLimitExceeded, "deny", domain.ReasonResourceOutputLimit, trace)),
		run: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, mut string) (domain.ExitCode, error) {
			srv := newG15Server(g15Body(strings.Repeat("x", 64<<10)))
			defer srv.Close()
			if err := g15Grant(ctx, stack, domain.ActionNetFetch, srv.Host); err != nil {
				return domain.ExitInternalError, err
			}
			tok, err := g15Token(stack, "net:fetch:"+srv.Host)
			if err != nil {
				return domain.ExitInternalError, err
			}
			lim := orchestrator.DefaultLimits()
			lim.MaxOutputBytes = parentLimit
			res, err := g15SpawnWorker(ctx, env, stack, g15Spawn{netAllow: []string{srv.Host}, limits: lim},
				subagent.SubagentRequest{TraceID: trace, Token: tok, Action: string(domain.ActionNetFetch), FilePath: "http://" + srv.Host + "/big"})
			if err != nil {
				return domain.ExitInternalError, err
			}
			code := domain.ExitCode(res.ExitCode)
			if srv.Hits() < 1 {
				return code, harness.Invariantf("server never contacted: 시험이 가짜일 수 있음")
			}
			if len(res.StdoutRaw) > parentLimit {
				return code, harness.Invariantf("parent received %d bytes, limit %d", len(res.StdoutRaw), parentLimit)
			}
			return code, nil
		},
	}
}

// ----------------------------------------------------------------------------
// E2E-79: 포트 단위 격리 대조군 쌍
// ----------------------------------------------------------------------------
func newG15E2E79() harness.Scenario {
	const trace = "trace-e2e-79-exp"
	return &g15Scenario{
		meta: g15Meta("E2E-79", "포트 단위 격리 대조군 쌍",
			"격리된 정직 워커는 허용 포트에서 응답을 받고, PEP 를 건너뛰는 악의 워커는 다른 포트에 연결하지 못한다(대조군 쌍).",
			"OSConfinementBypass", "허용 포트는 열리고 나머지는 커널이 막습니다. 격리 끔(공격 성공)과 켬(차단) 쌍으로 부모가 직접 관찰했습니다.", true,
			g15Expect(domain.ExitPathViolation, orchestrator.AuditActionAgentConfined, "allow", "", trace)),
		run: func(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, mut string) (domain.ExitCode, error) {
			srv := newG15Server(g15Body("fetched"))
			defer srv.Close()
			if err := g15Grant(ctx, stack, domain.ActionNetFetch, srv.Host); err != nil {
				return domain.ExitInternalError, err
			}
			pol := confinement.WorkerPolicy(env.RootDir, env.WorkspaceDir, filepath.Dir(env.StatePath), env.AuditPath)
			pol.AllowConnectPorts = []int{srv.Port}
			platform := confinement.WithLauncher(confinement.Platform(), env.BinaryPath)

			// ① 격리된 정직 워커의 net:fetch (정책이 너무 좁아 모두 막히는 가짜 차단 배제)
			tok, err := g15Token(stack, "net:fetch:"+srv.Host)
			if err != nil {
				return domain.ExitInternalError, err
			}
			honest, err := g15SpawnWorker(ctx, env, stack, g15Spawn{netAllow: []string{srv.Host}, confiner: platform, policy: pol},
				subagent.SubagentRequest{TraceID: "trace-e2e-79-honest", Token: tok, Action: string(domain.ActionNetFetch), FilePath: "http://" + srv.Host + "/status"})
			if err != nil {
				return domain.ExitInternalError, err
			}
			if honest.ExitCode != 0 || srv.Hits() != 1 {
				return domain.ExitInternalError, harness.Invariantf("confined honest worker: exit=%d hits=%d, want 0/1", honest.ExitCode, srv.Hits())
			}

			// ② PEP 를 건너뛰는 악의 워커: 대조군(격리 없음) → 실험군(격리, 다른 포트 Q)
			ctlPol := pol
			ctlPol.Require = false
			cl, err := newG10Listener()
			if err != nil {
				return domain.ExitInternalError, err
			}
			defer cl.ln.Close()
			if err := g15FaultSpawn(ctx, env, stack, "trace-e2e-79-ctl", cl.ln.Addr().String(), confinement.NoopConfiner{}, ctlPol); err != nil {
				return domain.ExitInternalError, err
			}
			deadline := time.Now().Add(2 * time.Second)
			for cl.n.Load() < 1 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if cl.n.Load() != 1 {
				return domain.ExitInternalError, harness.Invariantf("대조군 accept=%d, want 1: 격리가 없는데도 막힘(가짜 시험)", cl.n.Load())
			}

			el, err := newG10Listener()
			if err != nil {
				return domain.ExitInternalError, err
			}
			defer el.ln.Close()
			expC, expPol := platform, pol
			if mut == "no-confinement" {
				expC = confinement.NoopConfiner{}
				expPol.Require = false
			}
			if err := g15FaultSpawn(ctx, env, stack, trace, el.ln.Addr().String(), expC, expPol); err != nil {
				return domain.ExitInternalError, err
			}
			time.Sleep(time.Second)
			if n := el.n.Load(); n != 0 {
				return domain.ExitInternalError, harness.Invariantf("실험군 accept=%d, want 0: 격리가 뚫림", n)
			}
			return domain.ExitPathViolation, nil
		},
	}
}

// g15FaultSpawn 은 bypass_open_socket 결함 워커를 주어진 격리로 스폰하고, 자식이 실제로 실행되었음을 확인한다.
func g15FaultSpawn(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, trace, target string, c confinement.Confiner, pol confinement.Policy) error {
	sp, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath:  env.FaultWorkerPath,
		Args:        []string{"-mode", "bypass_open_socket", "-target", target},
		Limits:      orchestrator.Limits{Timeout: 10 * time.Second},
		Audit:       stack.AuditWriter,
		Confiner:    c,
		Confinement: pol,
	})
	if err != nil {
		return err
	}
	res, err := sp.Spawn(ctx, subagent.SubagentRequest{Version: "1.0", TraceID: trace, Action: string(domain.ActionFileRead), FilePath: "g15"})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 || !strings.Contains(res.StdoutRaw, "RESULT=") {
		return harness.Invariantf("faultworker 가 실행되지 않음(exit=%d): 차단이 아니라 미실행일 수 있음", res.ExitCode)
	}
	return nil
}
