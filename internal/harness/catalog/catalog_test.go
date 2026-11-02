package catalog

import (
	"context"
	"testing"

	"authz-harness/internal/harness"
)

// TestCatalog_ScenarioCount32 는 카탈로그에 32개의 고유 시나리오가 등록되어 있는지 검증한다.
func TestCatalog_ScenarioCount32(t *testing.T) {
	scenarios := AllScenarios()
	if len(scenarios) != 32 {
		t.Fatalf("expected 32 scenarios, got %d", len(scenarios))
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

// TestCatalog_RegisterAll 은 Runner에 32개 시나리오가 정상 등록되는지 검증한다.
func TestCatalog_RegisterAll(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	if err := RegisterAll(runner); err != nil {
		t.Fatalf("RegisterAll failed: %v", err)
	}

	list := runner.List()
	if len(list) != 32 {
		t.Fatalf("expected 32 registered scenarios, got %d", len(list))
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

// TestCatalog_RunAll_QuadAssertion 은 30개 전체 시나리오를 일괄 실행하여 100% PASS 되는지 검증한다.
func TestCatalog_RunAll_QuadAssertion(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	if err := RegisterAll(runner); err != nil {
		t.Fatalf("RegisterAll failed: %v", err)
	}

	results, err := runner.RunAll(context.Background())
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	if len(results) != 32 {
		t.Fatalf("expected 32 results, got %d", len(results))
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
		t.Fatalf("Total %d / 30 scenarios failed", failedCount)
	}
}
