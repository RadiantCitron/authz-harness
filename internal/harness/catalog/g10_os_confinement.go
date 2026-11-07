package catalog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// G10: OS 수준 격리 및 악의 워커 차단 (E2E-45 ~ E2E-49)
//
// 모든 판정은 부모가 관찰한 사실(canary·파일·리스너)로만 내린다. 자식의 종료 코드나 자기보고는 근거가 아니다.
// 대조군(격리 꺼짐: 공격 성공 관찰) → 실험군(격리 켜짐: 차단 관찰) 쌍이 모두 성립할 때만 PASS 다.
func g10Scenarios() []harness.Scenario {
	return withStages([]harness.Scenario{
		&g10Scenario{id: "E2E-45", name: "PEP 우회 Zone A 개인키 영역 직접 읽기 차단", attack: g10Read,
			desc: "악의 워커가 PEP 를 건너뛰고 zone_a 의 canary 를 직접 읽으려 한다. 대조군에서는 유출, 실험군에서는 커널이 차단한다."},
		&g10Scenario{id: "E2E-46", name: "PEP 우회 샌드박스 밖 직접 쓰기 차단", attack: g10Write,
			desc: "악의 워커가 샌드박스 밖 경로에 파일을 직접 쓰려 한다. 대조군에서는 생성, 실험군에서는 미생성."},
		&g10Scenario{id: "E2E-47", name: "PEP 우회 네트워크 소켓 연결 차단", attack: g10Socket,
			desc: "악의 워커가 부모의 로컬 리스너에 TCP 연결을 시도한다. 대조군 accept 1건, 실험군 0건."},
		&g10Scenario{id: "E2E-48", name: "손자 프로세스의 격리 상속", attack: g10Grandchild,
			desc: "악의 워커가 자기 자식을 통해 zone_a 를 읽는다. 격리는 자손에게 상속되어 canary 가 유출되지 않는다."},
		&g10Scenario{id: "E2E-49", name: "격리 필수 모드 Fail-Closed", attack: g10FailClosed,
			desc: "격리를 적용할 수 없는 필수 모드(NoopConfiner)에서는 자식을 기동하지 않고 16 으로 거부한다."},
	})
}

type g10Attack int

const (
	g10Read g10Attack = iota
	g10Write
	g10Socket
	g10Grandchild
	g10FailClosed
)

type g10Scenario struct {
	id, name, desc string
	attack         g10Attack

	// 변이 검증(TC-050-03/04)에서만 쓰는 시험 주입점. nil 이면 Platform().
	experimentOverride confinement.Confiner
	controlOverride    confinement.Confiner
}

func (s *g10Scenario) traceID(phase string) string {
	return "trace-" + strings.ToLower(s.id) + "-" + phase
}

func (s *g10Scenario) Metadata() harness.ScenarioMetadata {
	exp := harness.ExpectedAssertion{
		ExitCode: domain.ExitPathViolation, // 부모의 판정: 차단 관찰됨
		Audit: harness.AuditExpectation{
			RequireEvent:     true,
			ExpectedAction:   orchestrator.AuditActionAgentConfined,
			ExpectedDecision: "allow",
			ExpectedTraceID:  s.traceID("exp"),
		},
		HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
	}
	if s.attack == g10FailClosed {
		exp.ExitCode = domain.ExitInternalError
		exp.Audit.ExpectedDecision = "deny"
		exp.Audit.ExpectedReason = domain.ReasonConfinementUnavailable
	}
	return harness.ScenarioMetadata{
		ID:                  s.id,
		Group:               "G10",
		Name:                s.name,
		Description:         s.desc,
		AttackClass:         "OSConfinementBypass",
		ParadoxExplanation:  "PEP 를 건너뛰는 악의 워커도, 앱 코드가 아니라 OS 커널이 막았음을 격리 끔/켬 쌍 대조로 부모가 관찰했습니다.",
		RequiresSubprocess:  true,
		RequiresConfinement: true,
		Expected:            exp,
	}
}

func (s *g10Scenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	return precreateAuditLock(env)
}

func (s *g10Scenario) spawn(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack, trace, mode, target string,
	c confinement.Confiner, pol confinement.Policy) (*orchestrator.SpawnResult, error) {
	sp, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath:  env.FaultWorkerPath,
		Args:        []string{"-mode", mode, "-target", target},
		Limits:      orchestrator.Limits{Timeout: 10 * time.Second},
		Audit:       stack.AuditWriter,
		Confiner:    c,
		Confinement: pol,
	})
	if err != nil {
		return nil, err
	}
	return sp.Spawn(ctx, subagent.SubagentRequest{
		Version: "1.0", TraceID: trace, Action: string(domain.ActionFileRead), FilePath: "g10",
	})
}

func newCanary() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *g10Scenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	root := env.RootDir
	zoneB := filepath.Dir(env.StatePath)
	pol := confinement.WorkerPolicy(root, env.WorkspaceDir, zoneB, env.AuditPath)
	platform := confinement.WithLauncher(confinement.Platform(), env.BinaryPath)

	expC, expPol := platform, pol
	if s.experimentOverride != nil {
		expC = s.experimentOverride
		expPol.Require = false
	}
	ctlC, ctlPol := confinement.Confiner(confinement.NoopConfiner{}), pol
	ctlPol.Require = false
	if s.controlOverride != nil {
		ctlC = confinement.WithLauncher(s.controlOverride, env.BinaryPath)
	}

	switch s.attack {
	case g10FailClosed:
		return s.executeFailClosed(ctx, env, stack, platform, pol)
	case g10Socket:
		return s.executeSocket(ctx, env, stack, ctlC, ctlPol, expC, expPol)
	case g10Write:
		return s.executeWrite(ctx, env, stack, ctlC, ctlPol, expC, expPol)
	}

	// 읽기 계열 (E2E-45, E2E-48)
	mode := "bypass_read_zone_a"
	if s.attack == g10Grandchild {
		mode = "bypass_child_read_zone_a"
	}
	canary, err := newCanary()
	if err != nil {
		return domain.ExitInternalError, err
	}
	canaryFile := filepath.Join(root, "zone_a", "canary.txt")
	if err := os.WriteFile(canaryFile, []byte(canary), 0o600); err != nil {
		return domain.ExitInternalError, err
	}

	// 1단계 대조군: 격리 꺼짐 → 공격 성공이 관찰되어야 한다.
	ctl, err := s.spawn(ctx, env, stack, s.traceID("ctl"), mode, canaryFile, ctlC, ctlPol)
	if err != nil {
		return domain.ExitInternalError, err
	}
	if !strings.Contains(ctl.StdoutRaw, canary) {
		return domain.ExitInternalError, harness.Invariantf("대조군에서 canary 유출이 관찰되지 않음: 격리가 없는데도 막힘(가짜 시험)")
	}

	// 2단계 실험군: 격리 켜짐 → 차단이 관찰되어야 한다.
	exp, err := s.spawn(ctx, env, stack, s.traceID("exp"), mode, canaryFile, expC, expPol)
	if err != nil {
		return domain.ExitInternalError, err
	}
	if exp.ExitCode != 0 || !strings.Contains(exp.StdoutRaw, "RESULT=") {
		return domain.ExitInternalError, harness.Invariantf("실험군 자식이 실행되지 않음(exit=%d): 차단이 아니라 미실행일 수 있음", exp.ExitCode)
	}
	if strings.Contains(exp.StdoutRaw, canary) {
		return domain.ExitInternalError, harness.Invariantf("실험군에서 canary 유출: 격리가 뚫림")
	}
	if b, err := os.ReadFile(canaryFile); err != nil || string(b) != canary {
		return domain.ExitInternalError, harness.Invariantf("부모가 canary 를 읽지 못함 또는 변조됨")
	}
	return domain.ExitPathViolation, nil
}

func (s *g10Scenario) executeWrite(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack,
	ctlC confinement.Confiner, ctlPol confinement.Policy, expC confinement.Confiner, expPol confinement.Policy) (domain.ExitCode, error) {
	outside, err := os.MkdirTemp("", "g10-outside-*")
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer os.RemoveAll(outside)

	ctlFile := filepath.Join(outside, "outside_control.txt")
	if _, err := s.spawn(ctx, env, stack, s.traceID("ctl"), "bypass_write_outside", ctlFile, ctlC, ctlPol); err != nil {
		return domain.ExitInternalError, err
	}
	if _, err := os.Stat(ctlFile); err != nil {
		return domain.ExitInternalError, harness.Invariantf("대조군에서 파일 생성이 관찰되지 않음: 격리가 없는데도 막힘(가짜 시험)")
	}
	_ = os.Remove(ctlFile)

	target := filepath.Join(outside, "outside_target.txt")
	exp, err := s.spawn(ctx, env, stack, s.traceID("exp"), "bypass_write_outside", target, expC, expPol)
	if err != nil {
		return domain.ExitInternalError, err
	}
	if exp.ExitCode != 0 || !strings.Contains(exp.StdoutRaw, "RESULT=") {
		return domain.ExitInternalError, harness.Invariantf("실험군 자식이 실행되지 않음(exit=%d)", exp.ExitCode)
	}
	if _, err := os.Stat(target); err == nil {
		return domain.ExitInternalError, harness.Invariantf("실험군에서 샌드박스 밖 파일이 생성됨: 격리가 뚫림")
	}
	return domain.ExitPathViolation, nil
}

// g10Listener 는 accept 건수를 세는 부모 리스너다.
type g10Listener struct {
	ln net.Listener
	n  atomic.Int32
}

func newG10Listener() (*g10Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l := &g10Listener{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.n.Add(1)
			_ = c.Close()
		}
	}()
	return l, nil
}

func (s *g10Scenario) executeSocket(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack,
	ctlC confinement.Confiner, ctlPol confinement.Policy, expC confinement.Confiner, expPol confinement.Policy) (domain.ExitCode, error) {
	cl, err := newG10Listener()
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer cl.ln.Close()
	if _, err := s.spawn(ctx, env, stack, s.traceID("ctl"), "bypass_open_socket", cl.ln.Addr().String(), ctlC, ctlPol); err != nil {
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
	exp, err := s.spawn(ctx, env, stack, s.traceID("exp"), "bypass_open_socket", el.ln.Addr().String(), expC, expPol)
	if err != nil {
		return domain.ExitInternalError, err
	}
	if exp.ExitCode != 0 || !strings.Contains(exp.StdoutRaw, "RESULT=") {
		return domain.ExitInternalError, harness.Invariantf("실험군 자식이 실행되지 않음(exit=%d)", exp.ExitCode)
	}
	time.Sleep(time.Second) // deadline 안에 accept 가 없어야 한다
	if n := el.n.Load(); n != 0 {
		return domain.ExitInternalError, harness.Invariantf("실험군 accept=%d, want 0: 격리가 뚫림", n)
	}
	return domain.ExitPathViolation, nil
}

func (s *g10Scenario) executeFailClosed(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack,
	platform confinement.Confiner, pol confinement.Policy) (domain.ExitCode, error) {
	content := "g10 workspace baseline"
	wsFile := filepath.Join(env.WorkspaceDir, "honest.txt")
	if err := os.WriteFile(wsFile, []byte(content), 0o600); err != nil {
		return domain.ExitInternalError, err
	}
	// 1단계: 정직한 정책으로 허용 경로가 실제로 열려 있음을 확인 (너무 좁아서 모두 막히는 가짜 차단 배제)
	ok, err := s.spawn(ctx, env, stack, s.traceID("ctl"), "bypass_read_zone_a", wsFile, platform, pol)
	if err != nil {
		return domain.ExitInternalError, err
	}
	if !strings.Contains(ok.StdoutRaw, content) {
		return domain.ExitInternalError, harness.Invariantf("격리 하에서 허용 경로(workspace) 읽기가 실패: 정책이 너무 좁음(exit=%d)", ok.ExitCode)
	}
	// 2단계: 필수 모드 + NoopConfiner → 자식 미기동
	strict := pol
	strict.Require = true
	res, err := s.spawn(ctx, env, stack, s.traceID("exp"), "bypass_read_zone_a", wsFile, confinement.NoopConfiner{}, strict)
	if err != nil {
		return domain.ExitInternalError, err
	}
	if res.StdoutRaw != "" || res.RawExitCode != -1 {
		return domain.ExitInternalError, harness.Invariantf("필수 모드인데 자식이 기동됨")
	}
	return domain.ExitCode(res.ExitCode), nil
}
