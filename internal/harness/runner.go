package harness

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
)

// ExecutionMode 는 E2E 하네스 시나리오의 실행 격리 모드를 정의한다.
type ExecutionMode string

const (
	// ModeSubprocess 는 독립된 OS 자식 프로세스(`authz-harness subagent worker`)를 스폰하여 실행하는 표준 모드다.
	ModeSubprocess ExecutionMode = "subprocess"

	// ModeInProc 는 단일 프로세스 메모리 내에서 PEP Gateway를 직접 호출하는 고속 실행 모드다.
	ModeInProc ExecutionMode = "inproc"
)

// ScenarioResult 는 단일 시나리오의 종합 실행 결과다.
type ScenarioResult struct {
	Metadata  ScenarioMetadata `json:"metadata"`
	Passed    bool             `json:"passed"`
	Duration  time.Duration    `json:"duration"`
	Assertion AssertionResult  `json:"assertion"`
	Error     string           `json:"error,omitempty"`
	Skipped   bool             `json:"skipped,omitempty"`
}

// Runner 는 시나리오들을 등록하고 독립 샌드박스에서 실행하는 오케스트레이터다.
type Runner interface {
	// Register 는 카탈로그에 시나리오를 등록한다.
	Register(s Scenario) error

	// Get 은 ID로 시나리오를 조회한다.
	Get(id string) (Scenario, bool)

	// List 는 등록된 모든 시나리오 메타데이터 목록을 반환한다.
	List() []ScenarioMetadata

	// RunScenario 는 단일 시나리오를 격리 샌드박스에서 실행하고 Quad-Assertion을 수행한다.
	RunScenario(ctx context.Context, id string) (ScenarioResult, error)

	// RunAll 은 등록된 모든 시나리오를 순차 실행하고 결과를 수집한다.
	RunAll(ctx context.Context) ([]ScenarioResult, error)
}

// DefaultRunner 는 Runner 인터페이스의 표준 구현체다.
type DefaultRunner struct {
	mu                  sync.RWMutex
	scenarios           map[string]Scenario
	order               []string
	evaluator           Evaluator
	baseDir             string
	executionMode       ExecutionMode
	binaryProvider      BinaryProvider
	faultWorkerProvider BinaryProvider
	confinementProbe    func() bool
}

// RunnerOption 은 Runner 생성 옵션이다.
type RunnerOption func(*DefaultRunner)

// WithExecutionMode 는 실행 모드(subprocess | inproc)를 지정하는 옵션이다.
func WithExecutionMode(mode ExecutionMode) RunnerOption {
	return func(r *DefaultRunner) {
		r.executionMode = mode
	}
}

// WithBinaryProvider 는 서브프로세스 바이너리 프로바이더를 주입하는 옵션이다.
func WithBinaryProvider(provider BinaryProvider) RunnerOption {
	return func(r *DefaultRunner) {
		r.binaryProvider = provider
	}
}

// WithFaultWorkerProvider 는 결함 워커 프로바이더를 주입하는 옵션이다.
func WithFaultWorkerProvider(provider BinaryProvider) RunnerOption {
	return func(r *DefaultRunner) {
		r.faultWorkerProvider = provider
	}
}

// WithConfinementProbe 는 커널 격리 적용 가능 여부 프로브를 주입한다. 기본값은 confinement.Platform().Available 이다.
func WithConfinementProbe(probe func() bool) RunnerOption {
	return func(r *DefaultRunner) {
		r.confinementProbe = probe
	}
}

// WithEvaluator 는 커스텀 Evaluator 를 주입하는 옵션이다.
func WithEvaluator(eval Evaluator) RunnerOption {
	return func(r *DefaultRunner) {
		r.evaluator = eval
	}
}

// WithBaseDir 은 샌드박스 생성 시 사용할 기본 디렉터리를 지정하는 옵션이다.
func WithBaseDir(dir string) RunnerOption {
	return func(r *DefaultRunner) {
		r.baseDir = dir
	}
}

// NewDefaultRunner 는 DefaultRunner 인스턴스를 생성한다.
func NewDefaultRunner(opts ...RunnerOption) *DefaultRunner {
	r := &DefaultRunner{
		scenarios:     make(map[string]Scenario),
		order:         make([]string, 0),
		evaluator:     NewDefaultEvaluator(),
		executionMode: ModeSubprocess, // 기본값: 실제 OS 서브프로세스 격리 모드
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.confinementProbe == nil {
		r.confinementProbe = confinement.Platform().Available
	}
	if r.executionMode == ModeSubprocess && r.binaryProvider == nil {
		r.binaryProvider = NewCachedBinaryProvider()
	}
	if r.executionMode == ModeSubprocess && r.faultWorkerProvider == nil {
		r.faultWorkerProvider = NewFaultWorkerProvider()
	}
	return r
}

// Register 는 시나리오를 러너에 등록한다.
func (r *DefaultRunner) Register(s Scenario) error {
	if s == nil {
		return fmt.Errorf("harness runner: scenario is nil")
	}
	meta := s.Metadata()
	if meta.ID == "" {
		return fmt.Errorf("harness runner: scenario ID cannot be empty")
	}

	if meta.Expected.Audit.ExpectedStage == "" {
		return fmt.Errorf("harness runner: scenario %q has no expected audit stage", meta.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.scenarios[meta.ID]; exists {
		return fmt.Errorf("harness runner: scenario %q already registered", meta.ID)
	}

	r.scenarios[meta.ID] = s
	r.order = append(r.order, meta.ID)
	return nil
}

// Get 은 ID로 등록된 시나리오를 조회한다.
func (r *DefaultRunner) Get(id string) (Scenario, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scenarios[id]
	return s, ok
}

// List 는 등록된 모든 시나리오 메타데이터 목록을 등록 순서대로 반환한다.
func (r *DefaultRunner) List() []ScenarioMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]ScenarioMetadata, 0, len(r.order))
	for _, id := range r.order {
		list = append(list, r.scenarios[id].Metadata())
	}
	return list
}

// RunScenario 는 단일 시나리오를 격리 샌드박스에서 실행하고 Quad-Assertion을 수행한다.
func (r *DefaultRunner) RunScenario(ctx context.Context, id string) (ScenarioResult, error) {
	r.mu.RLock()
	s, ok := r.scenarios[id]
	r.mu.RUnlock()

	if !ok {
		return ScenarioResult{}, fmt.Errorf("harness runner: scenario %q not found", id)
	}

	meta := s.Metadata()
	startTime := time.Now()

	// 실행 모드 선언: 실제 OS 프로세스가 필요한 시나리오는 inproc 에서 건너뛴다 (샌드박스 생성 전).
	if meta.RequiresSubprocess && r.executionMode != ModeSubprocess {
		return ScenarioResult{Metadata: meta, Skipped: true, Passed: false, Error: "requires subprocess mode"}, nil
	}

	// 커널 격리가 필요한 시나리오는 적용 불가 환경(중첩 샌드박스 등)에서 건너뛴다. 폴백 없음.
	if meta.RequiresConfinement && !r.confinementProbe() {
		return ScenarioResult{Metadata: meta, Skipped: true, Passed: false, Error: "requires kernel confinement"}, nil
	}

	// 1. 시나리오별 격리 Ephemeral Sandbox 생성
	env, err := NewSandboxEnvironment(SandboxConfig{
		BaseDir: r.baseDir,
	})
	if err != nil {
		return ScenarioResult{
			Metadata: meta,
			Passed:   false,
			Duration: time.Since(startTime),
			Error:    fmt.Sprintf("failed to create sandbox environment: %v", err),
		}, err
	}
	defer func() {
		_ = env.Cleanup()
	}()

	// 서브프로세스 모드인 경우 컴파일된 바이너리 경로 주입
	if r.executionMode == ModeSubprocess && r.binaryProvider != nil {
		binPath, err := r.binaryProvider.GetBinaryPath()
		if err != nil {
			return ScenarioResult{
				Metadata: meta,
				Passed:   false,
				Duration: time.Since(startTime),
				Error:    fmt.Sprintf("failed to acquire test binary: %v", err),
			}, err
		}
		env.BinaryPath = binPath

		if meta.RequiresSubprocess && r.faultWorkerProvider != nil {
			fwPath, err := r.faultWorkerProvider.GetBinaryPath()
			if err != nil {
				return ScenarioResult{
					Metadata: meta,
					Passed:   false,
					Duration: time.Since(startTime),
					Error:    fmt.Sprintf("failed to acquire fault worker binary: %v", err),
				}, err
			}
			env.FaultWorkerPath = fwPath
		}
	}

	// 2. Setup 단계 실행
	if err := s.Setup(ctx, env); err != nil {
		duration := time.Since(startTime)
		return ScenarioResult{
			Metadata: meta,
			Passed:   false,
			Duration: duration,
			Error:    fmt.Sprintf("setup failed: %v", err),
		}, err
	}

	// 3. Execute 단계 실행 (종료 코드 수거)
	actualExitCode, execErr := s.Execute(ctx, env)
	var execErrMsg string
	if execErr != nil {
		execErrMsg = execErr.Error()
	}

	// 4. Quad-Assertion 불변식 판정
	assertionRes := r.evaluator.Evaluate(env, actualExitCode, meta.Expected)
	duration := time.Since(startTime)

	var iv *InvariantViolation
	invariantBroken := errors.As(execErr, &iv)
	if invariantBroken {
		assertionRes.FailureReasons = append(assertionRes.FailureReasons, "invariant violation: "+iv.Detail)
	}

	overallPassed := assertionRes.Passed && !invariantBroken &&
		(execErr == nil || actualExitCode != domain.ExitSuccess)

	return ScenarioResult{
		Metadata:  meta,
		Passed:    overallPassed,
		Duration:  duration,
		Assertion: assertionRes,
		Error:     execErrMsg,
	}, nil
}

// RunAll 은 등록된 모든 시나리오를 순차 실행하고 결과를 수집한다.
func (r *DefaultRunner) RunAll(ctx context.Context) ([]ScenarioResult, error) {
	r.mu.RLock()
	ids := make([]string, len(r.order))
	copy(ids, r.order)
	r.mu.RUnlock()

	results := make([]ScenarioResult, 0, len(ids))
	for _, id := range ids {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		res, _ := r.RunScenario(ctx, id)
		results = append(results, res)
	}

	return results, nil
}
