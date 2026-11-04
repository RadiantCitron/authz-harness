package catalog

import (
	"context"
	"os"
	"strings"
	"testing"

	"time"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/orchestrator"
)

// TestCatalog_ScenarioCount 는 카탈로그에 54개의 고유 시나리오가 등록되어 있는지 검증한다.
func TestCatalog_ScenarioCount(t *testing.T) {
	scenarios := AllScenarios()
	if len(scenarios) != 54 {
		t.Fatalf("expected 54 scenarios, got %d", len(scenarios))
	}

	seen := make(map[string]bool)
	for _, sc := range scenarios {
		meta := sc.Metadata()
		if meta.ID == "" {
			t.Errorf("scenario ID must not be empty")
		}
		if seen[meta.ID] {
			t.Errorf("duplicate scenario ID: %s", meta.ID)
		}
		seen[meta.ID] = true

		if meta.Group == "" {
			t.Errorf("scenario %s group must not be empty", meta.ID)
		}
		if meta.Name == "" {
			t.Errorf("scenario %s name must not be empty", meta.ID)
		}
		if meta.ParadoxExplanation == "" {
			t.Errorf("scenario %s explanation must not be empty", meta.ID)
		}
	}
}

// TestCatalog_RegisterAll 은 Runner에 54개 시나리오가 정상 등록되는지 검증한다.
func TestCatalog_RegisterAll(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	if err := RegisterAll(runner); err != nil {
		t.Fatalf("RegisterAll failed: %v", err)
	}

	list := runner.List()
	if len(list) != 54 {
		t.Fatalf("expected 54 registered scenarios, got %d", len(list))
	}
}

// TestCatalog_Group_G1_Lifecycle 은 G1 그룹 (E2E-01 ~ E2E-03) 실행 검증
func TestCatalog_Group_G1_Lifecycle(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g1Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g1Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("RunScenario %s error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_Group_G2_AuthN 은 G2 그룹 (E2E-04 ~ E2E-06) 실행 검증
func TestCatalog_Group_G2_AuthN(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g2Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g2Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("RunScenario %s error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_Group_G3_TokenIntegrity 은 G3 그룹 (E2E-07 ~ E2E-13) 실행 검증
func TestCatalog_Group_G3_TokenIntegrity(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g3Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g3Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("RunScenario %s error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_Group_G4_ClaimsReplay 은 G4 그룹 (E2E-14 ~ E2E-18) 실행 검증
func TestCatalog_Group_G4_ClaimsReplay(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g4Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g4Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("RunScenario %s error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_Group_G5_DelegationPDP 은 G5 그룹 (E2E-19 ~ E2E-24) 실행 검증
func TestCatalog_Group_G5_DelegationPDP(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g5Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g5Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("RunScenario %s error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_Group_G6_JailPath 은 G6 그룹 (E2E-25 ~ E2E-27) 실행 검증
func TestCatalog_Group_G6_JailPath(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g6Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g6Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("RunScenario %s error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_Group_G7_ObservabilityAudit 은 G7 그룹 (E2E-28 ~ E2E-30) 실행 검증
func TestCatalog_Group_G7_ObservabilityAudit(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g7Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g7Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("RunScenario %s error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_Group_G8_MCPAdapter 는 G8 그룹 (E2E-33 ~ E2E-39) 실행 검증
func TestCatalog_Group_G8_MCPAdapter(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g8Scenarios() {
		_ = runner.Register(sc)
	}

	for _, sc := range g8Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("scenario %s failed with error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// TestCatalog_RunAll_QuadAssertion 은 54개 전체 시나리오를 일괄 실행하여 100% PASS 되는지 검증한다.
func TestCatalog_RunAll_QuadAssertion(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	if err := RegisterAll(runner); err != nil {
		t.Fatalf("RegisterAll failed: %v", err)
	}

	results, err := runner.RunAll(context.Background())
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	if len(results) != 54 {
		t.Fatalf("expected 54 results, got %d", len(results))
	}

	failedCount := 0
	for _, r := range results {
		if !r.Passed {
			failedCount++
			t.Errorf("Scenario %s FAILED: ExitCodeActual=%d FilePassed=%v AuditPassed=%v HashChainPassed=%v Reasons=%v Error=%s",
				r.Metadata.ID,
				r.Assertion.ExitCodeActual,
				r.Assertion.FilePassed,
				r.Assertion.AuditPassed,
				r.Assertion.HashChainPassed,
				r.Assertion.FailureReasons,
				r.Error,
			)
		}
	}

	if failedCount > 0 {
		t.Fatalf("Total %d / 54 scenarios failed", failedCount)
	}
}

// TestCatalog_Group_G9_ResourceLimits 는 G9 그룹 (E2E-40 ~ E2E-44) 실행 검증
func TestCatalog_Group_G9_ResourceLimits(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g9Scenarios() {
		_ = runner.Register(sc)
	}
	for _, sc := range g9Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("scenario %s failed with error: %v", id, err)
		}
		if !res.Passed {
			t.Errorf("Scenario %s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

// mutatedExpectation 은 기대 종료 코드를 바꾼 변이 시나리오다 (TC-050-02).
type mutatedExpectation struct {
	harness.Scenario
	code domain.ExitCode
}

func (m mutatedExpectation) Metadata() harness.ScenarioMetadata {
	meta := m.Scenario.Metadata()
	meta.Expected.ExitCode = m.code
	return meta
}

// TC-050-02: 기대 코드를 0 으로 바꾸면 FAIL 이어야 한다 (동어반복 판정 방지).
func TestG9_MutationExpectedExitCodeFails(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	_ = runner.Register(mutatedExpectation{Scenario: g9Scenarios()[0], code: domain.ExitSuccess})
	res, err := runner.RunScenario(context.Background(), "E2E-40")
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("mutated scenario must FAIL")
	}
}

// TC-050-03: 확인 대상 PID 를 살아 있는 프로세스로 바꾸면 불변식 위반으로 FAIL 이어야 한다.
func TestG9_MutationLivePIDFailsByInvariant(t *testing.T) {
	sc := &g9FaultScenario{id: "E2E-41", name: "mut", mode: "spawn_child_hang",
		limits: orchestrator.Limits{Timeout: 300 * time.Millisecond},
		reason: domain.ReasonResourceTimeout, term: orchestrator.TermTimedOut, checkGrandchild: true,
		pidOverride: func(int) int { return os.Getpid() }}
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	_ = runner.Register(sc)
	res, err := runner.RunScenario(context.Background(), "E2E-41")
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("live-PID mutation must FAIL")
	}
	found := false
	for _, r := range res.Assertion.FailureReasons {
		found = found || strings.Contains(r, "invariant violation")
	}
	if !found {
		t.Fatalf("expected invariant violation reason, got %v", res.Assertion.FailureReasons)
	}
}

// TC-050-04: inproc 모드에서는 G9 전부 Skipped 이고 실패가 아니다.
func TestG9_SkippedInProc(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()), harness.WithExecutionMode(harness.ModeInProc))
	for _, sc := range g9Scenarios() {
		_ = runner.Register(sc)
	}
	for _, sc := range g9Scenarios() {
		res, err := runner.RunScenario(context.Background(), sc.Metadata().ID)
		if err != nil || !res.Skipped {
			t.Fatalf("%s: skipped=%v err=%v", sc.Metadata().ID, res.Skipped, err)
		}
	}
}

// TestG10: OS 격리 대조군→실험군 (E2E-45 ~ E2E-54). 격리 불가 환경에서는 Skipped 이며 실패가 아니다.
func TestG10_Scenarios(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g10Scenarios() {
		_ = runner.Register(sc)
	}
	for _, sc := range g10Scenarios() {
		id := sc.Metadata().ID
		res, err := runner.RunScenario(context.Background(), id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if res.Skipped {
			t.Logf("%s skipped: %s", id, res.Error)
			continue
		}
		if !res.Passed {
			t.Errorf("%s FAILED: reasons=%v err=%s", id, res.Assertion.FailureReasons, res.Error)
		}
	}
}

func g10RunMutant(t *testing.T, sc *g10Scenario) harness.ScenarioResult {
	t.Helper()
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	if !confinement.Platform().Available() {
		t.Skip("confinement unavailable")
	}
	_ = runner.Register(sc)
	res, err := runner.RunScenario(context.Background(), sc.id)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasInvariant(res harness.ScenarioResult) bool {
	for _, r := range res.Assertion.FailureReasons {
		if strings.Contains(r, "invariant violation") {
			return true
		}
	}
	return false
}

// TC-050-03: 실험군에 격리 끔(Noop)을 주입하면 canary 유출로 FAIL 이어야 한다.
func TestG10_MutationExperimentWithoutConfinementFails(t *testing.T) {
	res := g10RunMutant(t, &g10Scenario{id: "E2E-45", name: "mut", attack: g10Read, experimentOverride: confinement.NoopConfiner{}})
	if res.Passed || !hasInvariant(res) {
		t.Fatalf("must FAIL by invariant: %+v", res.Assertion.FailureReasons)
	}
}

// TC-050-04: 대조군에 실제 격리를 주입하면 "격리가 없는데도 막힘"으로 FAIL 이어야 한다.
func TestG10_MutationControlWithConfinementFails(t *testing.T) {
	res := g10RunMutant(t, &g10Scenario{id: "E2E-45", name: "mut", attack: g10Read, controlOverride: confinement.Platform()})
	if res.Passed || !hasInvariant(res) {
		t.Fatalf("must FAIL by invariant: %+v", res.Assertion.FailureReasons)
	}
}

// TC-050-02: 프로브가 false 이면 G10 5건 모두 Skipped.
func TestG10_SkippedWhenProbeFalse(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()), harness.WithConfinementProbe(func() bool { return false }))
	for _, sc := range g10Scenarios() {
		_ = runner.Register(sc)
	}
	for _, sc := range g10Scenarios() {
		res, err := runner.RunScenario(context.Background(), sc.Metadata().ID)
		if err != nil || !res.Skipped || res.Passed {
			t.Fatalf("%s: skipped=%v err=%v", sc.Metadata().ID, res.Skipped, err)
		}
	}
}

// TC-050-05: inproc 모드에서는 G10 전부 Skipped.
func TestG10_SkippedInProc(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()), harness.WithExecutionMode(harness.ModeInProc))
	for _, sc := range g10Scenarios() {
		_ = runner.Register(sc)
	}
	for _, sc := range g10Scenarios() {
		res, err := runner.RunScenario(context.Background(), sc.Metadata().ID)
		if err != nil || !res.Skipped {
			t.Fatalf("%s: skipped=%v err=%v", sc.Metadata().ID, res.Skipped, err)
		}
	}
}
