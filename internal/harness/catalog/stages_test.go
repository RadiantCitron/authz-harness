package catalog

import (
	"context"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// TC-060-03: 경계 단계 기대값을 바꾸는 변이(보고서 036 M1)는 시험이 실패해야 한다.
func TestStages_MutatedBoundaryExpectationFails(t *testing.T) {
	old := expectedStages["E2E-25"]
	expectedStages["E2E-25"] = domain.StageAuthz
	defer func() { expectedStages["E2E-25"] = old }()
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	for _, sc := range g6Scenarios() {
		_ = runner.Register(sc)
	}
	res, err := runner.RunScenario(context.Background(), "E2E-25")
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("mutated stage expectation must FAIL")
	}
}

// 표는 79건 전부를 덮어야 한다.
func TestStages_TableCoversAllScenarios(t *testing.T) {
	if n := len(AllScenarios()); n != len(expectedStages) {
		t.Fatalf("scenarios=%d stages=%d", n, len(expectedStages))
	}
	for _, s := range AllScenarios() {
		if s.Metadata().Expected.Audit.ExpectedStage == "" {
			t.Fatalf("%s has no expected stage", s.Metadata().ID)
		}
	}
}
