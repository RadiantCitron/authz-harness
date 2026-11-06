package catalog

import (
	"context"
	"testing"

	"authz-harness/internal/harness"
)

// TestG11: 예산 축소 위임 (E2E-50 ~ E2E-54)
func TestG11(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	t.Cleanup(func() { _ = runner.Close() })
	for _, sc := range g11Scenarios() {
		if err := runner.Register(sc); err != nil {
			t.Fatal(err)
		}
	}
	for _, sc := range g11Scenarios() {
		id := sc.Metadata().ID
		t.Run(id, func(t *testing.T) {
			res, err := runner.RunScenario(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Passed {
				t.Fatalf("FAILED: reasons=%v err=%s", res.Assertion.FailureReasons, res.Error)
			}
		})
	}
}

// E2E-52 는 inproc 모드에서 Skipped 이고 실패가 아니다.
func TestG11_E2E52SkippedInProc(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()), harness.WithExecutionMode(harness.ModeInProc))
	_ = runner.Register(stagedScenario{newG11E2E52()})
	res, err := runner.RunScenario(context.Background(), "E2E-52")
	if err != nil || !res.Skipped {
		t.Fatalf("skipped=%v err=%v", res.Skipped, err)
	}
}

// 변이 검증: 기대 종료 코드를 0 으로 바꾸면 FAIL 이어야 한다 (동어반복 판정 방지).
func TestG11_MutationExpectedExitCodeFails(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	t.Cleanup(func() { _ = runner.Close() })
	_ = runner.Register(mutatedExpectation{Scenario: stagedScenario{newG11E2E50()}, code: 0})
	res, err := runner.RunScenario(context.Background(), "E2E-50")
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("mutated scenario must FAIL")
	}
}
