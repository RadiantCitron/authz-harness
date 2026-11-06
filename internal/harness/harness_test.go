package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// AT-01: TestSandboxEnvironment_CreateAndLayout
func TestSandboxEnvironment_CreateAndLayout(t *testing.T) {
	tempDir := t.TempDir()
	env, err := NewSandboxEnvironment(SandboxConfig{
		BaseDir:   tempDir,
		ClockTime: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("NewSandboxEnvironment failed: %v", err)
	}
	defer env.Cleanup()

	// Zone A/B/C 경로 확인
	if env.RootDir == "" || env.PrivKeyPath == "" || env.PubJWKSPath == "" ||
		env.StatePath == "" || env.ReplayPath == "" || env.WorkspaceDir == "" || env.AuditPath == "" {
		t.Fatalf("SandboxEnvironment paths must not be empty: %+v", env)
	}

	// 디렉터리 존재 여부 확인
	if _, err := os.Stat(filepath.Dir(env.PrivKeyPath)); err != nil {
		t.Errorf("Zone A dir missing: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(env.PubJWKSPath)); err != nil {
		t.Errorf("Zone B dir missing: %v", err)
	}
	if _, err := os.Stat(env.WorkspaceDir); err != nil {
		t.Errorf("Zone C workspace dir missing: %v", err)
	}
	if _, err := os.Stat(env.AuditPath); err != nil {
		t.Errorf("Audit log file missing: %v", err)
	}

	// 가상 시계 검증
	now := env.MockClock.Now()
	if now.Year() != 2026 || now.Month() != 11 || now.Day() != 1 {
		t.Errorf("expected mock clock 2026-11-01, got %v", now)
	}
}

// AT-02: TestSandboxEnvironment_Cleanup
func TestSandboxEnvironment_Cleanup(t *testing.T) {
	tempDir := t.TempDir()
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: tempDir})
	if err != nil {
		t.Fatalf("NewSandboxEnvironment failed: %v", err)
	}

	rootDir := env.RootDir
	// 파일 쓰기
	testFile := filepath.Join(env.WorkspaceDir, "dummy.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Cleanup 호출
	if err := env.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// 루트 디렉터리가 삭제되었는지 확인
	if _, err := os.Stat(rootDir); !os.IsNotExist(err) {
		t.Errorf("expected rootDir %s to be deleted, stat err: %v", rootDir, err)
	}
}

// AT-03: TestQuadAssertion_SuccessCase
func TestQuadAssertion_SuccessCase(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	// 1. 파일 생성
	filePath := "output.txt"
	expectedContent := "valid output content"
	fullPath := filepath.Join(env.WorkspaceDir, filePath)
	if err := os.WriteFile(fullPath, []byte(expectedContent), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// 2. 감사 이벤트 기록 (해시 체인 포함)
	writer, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		t.Fatalf("failed to open audit writer: %v", err)
	}

	ev1 := audit.Event{
		Timestamp: time.Now().UTC(),
		TraceID:   "trace-001",
		Actor:     "worker-01",
		Action:    "pep.allow",
		Decision:  "allow",
		Reason:    string(domain.ReasonAuthorized),
		Metadata:  make(map[string]interface{}),
	}
	ev1.Metadata["prev_hash"] = ""
	ev1.Metadata["curr_hash"] = audit.ComputeEventHash("", ev1)

	if err := writer.Log(ev1); err != nil {
		t.Fatalf("failed to log audit event: %v", err)
	}
	_ = writer.Close()

	// 3. 기대 스펙 및 검증
	exp := ExpectedAssertion{
		ExitCode: domain.ExitSuccess,
		File: FileExpectation{
			RelPath:         filePath,
			ExpectExist:     true,
			ExpectedContent: expectedContent,
		},
		Audit: AuditExpectation{
			RequireEvent:     true,
			ExpectedDecision: "allow",
			ExpectedReason:   domain.ReasonAuthorized,
			ExpectedTraceID:  "trace-001",
		},
		HashChain: HashChainExpectation{
			RequireValidChain: true,
			NoRawTokenLeak:    true,
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitSuccess, exp)

	if !res.Passed {
		t.Fatalf("expected assertion to pass, failure reasons: %v", res.FailureReasons)
	}
	if !res.ExitCodePassed || !res.FilePassed || !res.AuditPassed || !res.HashChainPassed {
		t.Fatalf("all 4 assertions must pass: %+v", res)
	}
}

// AT-04: TestQuadAssertion_ExitCodeMismatch
func TestQuadAssertion_ExitCodeMismatch(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	exp := ExpectedAssertion{
		ExitCode: domain.ExitSuccess,
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitTokenInvalid, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail due to exit code mismatch")
	}
	if res.ExitCodePassed {
		t.Fatal("ExitCodePassed should be false")
	}
}

// AT-05: TestQuadAssertion_FileZeroMutationViolation
func TestQuadAssertion_FileZeroMutationViolation(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	// 불법 1바이트 파일 기록 발생
	relPath := "secret.txt"
	if err := os.WriteFile(filepath.Join(env.WorkspaceDir, relPath), []byte("X"), 0600); err != nil {
		t.Fatalf("file write error: %v", err)
	}

	exp := ExpectedAssertion{
		ExitCode: domain.ExitAuthzDenied,
		File: FileExpectation{
			RelPath:            relPath,
			ExpectZeroMutation: true,
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitAuthzDenied, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail due to zero mutation violation")
	}
	if res.FilePassed {
		t.Fatal("FilePassed should be false")
	}
}

// AT-06: TestQuadAssertion_AuditReasonMismatch
func TestQuadAssertion_AuditReasonMismatch(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	// 감사 로그에 NO_ACTIVE_GRANT 기록
	writer, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		t.Fatalf("failed to open audit writer: %v", err)
	}
	_ = writer.Log(audit.Event{
		Timestamp: time.Now().UTC(),
		Decision:  "deny",
		Reason:    string(domain.ReasonNoActiveGrant),
	})
	_ = writer.Close()

	exp := ExpectedAssertion{
		ExitCode: domain.ExitAuthzDenied,
		Audit: AuditExpectation{
			ExpectedDecision: "deny",
			ExpectedReason:   domain.ReasonTokenExpired, // 불일치 기대
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitAuthzDenied, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail due to reason mismatch")
	}
	if res.AuditPassed {
		t.Fatal("AuditPassed should be false")
	}
}

// AT-07: TestQuadAssertion_HashChainBroken
func TestQuadAssertion_HashChainBroken(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	// 해시 체인이 손상된 2개 이벤트 직접 파일 기록 (외부 변조 시뮬레이션)
	lines := `{"timestamp":"2026-11-01T12:00:00Z","trace_id":"t1","actor":"w","action":"read","decision":"allow","prev_hash":"","curr_hash":"hash-111"}
{"timestamp":"2026-11-01T12:00:01Z","trace_id":"t1","actor":"w","action":"read","decision":"allow","prev_hash":"broken-mismatch-hash","curr_hash":"hash-222"}
`
	if err := os.WriteFile(env.AuditPath, []byte(lines), 0600); err != nil {
		t.Fatalf("failed to write broken audit log: %v", err)
	}

	exp := ExpectedAssertion{
		ExitCode: domain.ExitSuccess,
		HashChain: HashChainExpectation{
			RequireValidChain: true,
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitSuccess, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail due to broken hash chain")
	}
	if res.HashChainPassed {
		t.Fatal("HashChainPassed should be false")
	}
}

// AT-08: TestQuadAssertion_RawTokenLeakDetection
func TestQuadAssertion_RawTokenLeakDetection(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	// 감사 이벤트에 원시 JWT Bearer 토큰 문자열 누출 주입
	writer, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		t.Fatalf("failed to open audit writer: %v", err)
	}
	_ = writer.Log(audit.Event{
		Timestamp: time.Now().UTC(),
		Decision:  "allow",
		Metadata: map[string]interface{}{
			"raw_token": "eyJhbGciOiJFZERTQSI...eyJzdWIiOiJ3b3JrZXIifQ...abcdefg1234567890",
		},
	})
	_ = writer.Close()

	exp := ExpectedAssertion{
		ExitCode: domain.ExitSuccess,
		HashChain: HashChainExpectation{
			NoRawTokenLeak: true,
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitSuccess, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail due to raw token leak")
	}
	if res.HashChainPassed {
		t.Fatal("HashChainPassed should be false when raw token leaked")
	}
}

// dummyScenario 는 라이프사이클 테스트용 더미 시나리오다.
type dummyScenario struct {
	meta     ScenarioMetadata
	setupFn  func(ctx context.Context, env *SandboxEnvironment) error
	execFn   func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error)
}

func (d *dummyScenario) Metadata() ScenarioMetadata {
	return d.meta
}

func (d *dummyScenario) Setup(ctx context.Context, env *SandboxEnvironment) error {
	if d.setupFn != nil {
		return d.setupFn(ctx, env)
	}
	return nil
}

func (d *dummyScenario) Execute(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
	if d.execFn != nil {
		return d.execFn(ctx, env)
	}
	return domain.ExitSuccess, nil
}

// AT-09: TestHarnessRunner_LifecycleSmoke
func TestHarnessRunner_LifecycleSmoke(t *testing.T) {
	runner := NewDefaultRunner(WithBaseDir(t.TempDir()))
	t.Cleanup(func() { _ = runner.Close() })

	sc := &dummyScenario{
		meta: ScenarioMetadata{
			ID:          "E2E-TEST-01",
			Group:       "G1",
			Name:        "Smoke Lifecycle Test",
			Description: "Verify Setup -> Execute -> QuadAssert -> Teardown",
			Expected: ExpectedAssertion{
				ExitCode: domain.ExitSuccess,
				Audit:    AuditExpectation{ExpectedStage: NoStageRecord},
				File: FileExpectation{
					RelPath:         "hello.txt",
					ExpectExist:     true,
					ExpectedContent: "world",
				},
			},
		},
		setupFn: func(ctx context.Context, env *SandboxEnvironment) error {
			// Setup 시 초기 준비
			return nil
		},
		execFn: func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
			// Execute 시 파일 작성
			path := filepath.Join(env.WorkspaceDir, "hello.txt")
			if err := os.WriteFile(path, []byte("world"), 0600); err != nil {
				return domain.ExitInternalError, err
			}
			return domain.ExitSuccess, nil
		},
	}

	if err := runner.Register(sc); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	res, err := runner.RunScenario(context.Background(), "E2E-TEST-01")
	if err != nil {
		t.Fatalf("RunScenario error: %v", err)
	}

	if !res.Passed {
		t.Fatalf("expected scenario to pass, got failure reasons: %v, error: %s", res.Assertion.FailureReasons, res.Error)
	}
	if res.Metadata.ID != "E2E-TEST-01" {
		t.Errorf("expected ID E2E-TEST-01, got %s", res.Metadata.ID)
	}
}

// AT-10: TestHarnessRunner_NoCrossContamination
func TestHarnessRunner_NoCrossContamination(t *testing.T) {
	runner := NewDefaultRunner(WithBaseDir(t.TempDir()))
	t.Cleanup(func() { _ = runner.Close() })

	scA := &dummyScenario{
		meta: ScenarioMetadata{
			ID: "E2E-SC-A",
			Expected: ExpectedAssertion{
				ExitCode: domain.ExitSuccess,
				Audit:    AuditExpectation{ExpectedStage: NoStageRecord},
			},
		},
		execFn: func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
			// 시나리오 A: Zone C에 잔여물 생성
			contamFile := filepath.Join(env.WorkspaceDir, "contamination.txt")
			_ = os.WriteFile(contamFile, []byte("polluted"), 0600)
			return domain.ExitSuccess, nil
		},
	}

	var observedContamination bool
	scB := &dummyScenario{
		meta: ScenarioMetadata{
			ID: "E2E-SC-B",
			Expected: ExpectedAssertion{
				ExitCode: domain.ExitSuccess,
				Audit:    AuditExpectation{ExpectedStage: NoStageRecord},
				File: FileExpectation{
					RelPath:            "contamination.txt",
					ExpectZeroMutation: true,
				},
			},
		},
		execFn: func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
			// 시나리오 B: A의 잔여물이 존재하는지 검사
			if env.WorkspaceFileExists("contamination.txt") {
				observedContamination = true
			}
			return domain.ExitSuccess, nil
		},
	}

	_ = runner.Register(scA)
	_ = runner.Register(scB)

	resA, errA := runner.RunScenario(context.Background(), "E2E-SC-A")
	if errA != nil || !resA.Passed {
		t.Fatalf("Scenario A failed: %v", errA)
	}

	resB, errB := runner.RunScenario(context.Background(), "E2E-SC-B")
	if errB != nil || !resB.Passed {
		t.Fatalf("Scenario B failed: %v", errB)
	}

	if observedContamination {
		t.Fatal("Cross-contamination detected: Scenario B observed files from Scenario A!")
	}
}

// TC-050-01: 해시 누락 이벤트에 대한 RequireValidChain: true 거부 (AP-07 가짜 해시 통과 완전 제거)
func TestTC_050_01_MissingHashFails(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	// curr_hash 가 없는 가짜 감사 로그 직접 기록
	lines := `{"timestamp":"2026-11-01T12:00:00Z","trace_id":"t1","actor":"w","action":"read","decision":"allow"}
`
	if err := os.WriteFile(env.AuditPath, []byte(lines), 0600); err != nil {
		t.Fatalf("failed to write audit log: %v", err)
	}

	exp := ExpectedAssertion{
		ExitCode: domain.ExitSuccess,
		HashChain: HashChainExpectation{
			RequireValidChain: true,
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitSuccess, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail when curr_hash is missing with RequireValidChain: true")
	}
	if res.HashChainPassed {
		t.Fatal("expected HashChainPassed to be false")
	}
}

// TC-050-02: ExpectedAction 불일치 시 폴백 없이 즉시 실패 (AP-08 무단 폴백 제거)
func TestTC_050_02_ActionMismatchNoFallback(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	// "pep.allow" 액션과 AUTHORIZED 사유 기록
	writer, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		t.Fatalf("failed to open audit writer: %v", err)
	}
	_ = writer.Log(audit.Event{
		TraceID:  "trc-50-02",
		Actor:    "worker",
		Action:   "pep.allow",
		Decision: "allow",
		Reason:   string(domain.ReasonAuthorized),
		Success:  true,
	})
	_ = writer.Close()

	// 그러나 기대값은 "pep.deny" / "AUTHORIZED"
	exp := ExpectedAssertion{
		ExitCode: domain.ExitSuccess,
		Audit: AuditExpectation{
			RequireEvent:     true,
			ExpectedAction:   "pep.deny", // 불일치 액션
			ExpectedDecision: "allow",
			ExpectedReason:   domain.ReasonAuthorized,
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitSuccess, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail when ExpectedAction does not match (no fallback allowed)")
	}
	if res.AuditPassed {
		t.Fatal("expected AuditPassed to be false")
	}
}

// TC-050-03: ExpectedTraceID 불일치 시 즉시 실패
func TestTC_050_03_TraceIDMismatchFails(t *testing.T) {
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatalf("sandbox init failed: %v", err)
	}
	defer env.Cleanup()

	writer, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		t.Fatalf("failed to open audit writer: %v", err)
	}
	_ = writer.Log(audit.Event{
		TraceID:  "trc-actual",
		Actor:    "worker",
		Action:   "pep.allow",
		Decision: "allow",
		Reason:   string(domain.ReasonAuthorized),
		Success:  true,
	})
	_ = writer.Close()

	exp := ExpectedAssertion{
		ExitCode: domain.ExitSuccess,
		Audit: AuditExpectation{
			RequireEvent:    true,
			ExpectedAction:  "pep.allow",
			ExpectedTraceID: "trc-different-expected", // 불일치 TraceID
		},
	}

	evaluator := NewDefaultEvaluator()
	res := evaluator.Evaluate(env, domain.ExitSuccess, exp)

	if res.Passed {
		t.Fatal("expected assertion to fail when ExpectedTraceID does not match")
	}
	if res.AuditPassed {
		t.Fatal("expected AuditPassed to be false")
	}
}

// TC-010-01~03: 불변식 위반이 판정을 뒤집는지, 일반 에러는 기존 동작을 유지하는지 검증한다.
func TestRunner_InvariantViolationJudgement(t *testing.T) {
	tests := []struct {
		name         string
		code         domain.ExitCode
		err          error
		wantPassed   bool
		wantInvReason bool
	}{
		{"TC-010-01 에러 없음", domain.ExitAuthzDenied, nil, true, false},
		{"TC-010-02 불변식 위반", domain.ExitAuthzDenied, Invariantf("child alive"), false, true},
		{"TC-010-03 일반 에러 + 비0 코드", domain.ExitAuthzDenied, errors.New("audit write failed"), true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := NewDefaultRunner(WithBaseDir(t.TempDir()))
			t.Cleanup(func() { _ = runner.Close() })
			sc := &dummyScenario{
				meta: ScenarioMetadata{
					ID: "E2E-TEST-INV", Group: "G0", Name: "invariant",
					Expected: ExpectedAssertion{ExitCode: domain.ExitAuthzDenied, Audit: AuditExpectation{ExpectedStage: NoStageRecord}},
				},
				execFn: func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
					return tc.code, tc.err
				},
			}
			if err := runner.Register(sc); err != nil {
				t.Fatalf("Register: %v", err)
			}
			res, err := runner.RunScenario(context.Background(), "E2E-TEST-INV")
			if err != nil {
				t.Fatalf("RunScenario: %v", err)
			}
			if res.Passed != tc.wantPassed {
				t.Fatalf("Passed=%v want %v (reasons=%v)", res.Passed, tc.wantPassed, res.Assertion.FailureReasons)
			}
			found := false
			for _, r := range res.Assertion.FailureReasons {
				if strings.Contains(r, "invariant violation") {
					found = true
				}
			}
			if found != tc.wantInvReason {
				t.Fatalf("invariant reason present=%v want %v", found, tc.wantInvReason)
			}
		})
	}
}

type stubProvider struct{ path string }

func (s stubProvider) GetBinaryPath() (string, error) { return s.path, nil }

// TC-040-04: inproc 러너는 RequiresSubprocess 시나리오를 건너뛴다.
func TestRunner_RequiresSubprocessSkippedInProc(t *testing.T) {
	calls := 0
	sc := &dummyScenario{
		meta:    ScenarioMetadata{ID: "E2E-SUB", Group: "G9", RequiresSubprocess: true,
			Expected: ExpectedAssertion{Audit: AuditExpectation{ExpectedStage: NoStageRecord}}},
		setupFn: func(ctx context.Context, env *SandboxEnvironment) error { calls++; return nil },
		execFn: func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
			calls++
			return domain.ExitSuccess, nil
		},
	}
	runner := NewDefaultRunner(WithBaseDir(t.TempDir()), WithExecutionMode(ModeInProc))
	_ = runner.Register(sc)
	res, err := runner.RunScenario(context.Background(), "E2E-SUB")
	if err != nil || !res.Skipped || res.Passed || calls != 0 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, calls)
	}
}

// TC-040-05: 서브프로세스 러너는 RequiresSubprocess 시나리오에만 FaultWorkerPath 를 주입한다.
func TestRunner_InjectsFaultWorkerPath(t *testing.T) {
	var got, gotPlain string
	mk := func(id string, req bool, dst *string) *dummyScenario {
		return &dummyScenario{
			meta: ScenarioMetadata{ID: id, Group: "G9", RequiresSubprocess: req,
				Expected: ExpectedAssertion{ExitCode: domain.ExitSuccess, Audit: AuditExpectation{ExpectedStage: NoStageRecord}}},
			execFn: func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
				*dst = env.FaultWorkerPath
				return domain.ExitSuccess, nil
			},
		}
	}
	runner := NewDefaultRunner(WithBaseDir(t.TempDir()),
		WithBinaryProvider(stubProvider{"/bin/true"}),
		WithFaultWorkerProvider(stubProvider{"/bin/fw"}))
	_ = runner.Register(mk("E2E-A", true, &got))
	_ = runner.Register(mk("E2E-B", false, &gotPlain))
	for _, id := range []string{"E2E-A", "E2E-B"} {
		if _, err := runner.RunScenario(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if got != "/bin/fw" || gotPlain != "" {
		t.Fatalf("got=%q plain=%q", got, gotPlain)
	}
}
