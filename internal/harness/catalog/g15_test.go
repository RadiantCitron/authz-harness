package catalog

import (
	"context"
	"testing"

	"authz-harness/internal/confinement"
	"authz-harness/internal/harness"
)

func runG15(t *testing.T, sc harness.Scenario) harness.ScenarioResult {
	t.Helper()
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	t.Cleanup(func() { _ = runner.Close() })
	if err := runner.Register(stagedScenario{sc}); err != nil {
		t.Fatal(err)
	}
	res, err := runner.RunScenario(context.Background(), sc.Metadata().ID)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TC-060-01: G15 6건 PASS (격리 불가 환경에서 E2E-79 는 Skipped)
func TestG15_Scenarios(t *testing.T) {
	for _, sc := range g15Scenarios() {
		id := sc.Metadata().ID
		t.Run(id, func(t *testing.T) {
			res := runG15(t, sc)
			if res.Skipped {
				t.Skipf("skipped: %s", res.Error)
			}
			if !res.Passed {
				t.Fatalf("FAILED: reasons=%v err=%s", res.Assertion.FailureReasons, res.Error)
			}
		})
	}
}

// TC-060-02: 변이 — 판정기가 실제로 판정한다.
func TestG15_Mutations(t *testing.T) {
	cases := []struct {
		name string
		sc   *g15Scenario
		need bool // 격리 필요
	}{
		{"E2E-75 allow-list 에 Q 추가", newG15E2E75().(*g15Scenario), false},
		{"E2E-74 기대 result_hash 변조", newG15E2E74().(*g15Scenario), false},
		{"E2E-79 실험군을 Noop 으로", newG15E2E79().(*g15Scenario), true},
	}
	cases[0].sc.mut = "allow-q"
	cases[1].sc.mut = "bad-result-hash"
	cases[2].sc.mut = "no-confinement"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.need && !confinement.Platform().Available() {
				t.Skip("confinement unavailable")
			}
			res := runG15(t, c.sc)
			if res.Passed {
				t.Fatal("mutant must FAIL")
			}
		})
	}
}
