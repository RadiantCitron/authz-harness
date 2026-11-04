package catalog

import (
	"context"
	"testing"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// TestG12: 장기 실행 및 토큰 수명 검증 (E2E-55 ~ E2E-60), 인프로세스 모드
func TestG12(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()), harness.WithExecutionMode(harness.ModeInProc))
	for _, sc := range g12Scenarios() {
		if err := runner.Register(sc); err != nil {
			t.Fatal(err)
		}
	}
	for _, sc := range g12Scenarios() {
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

// 변이 검증 (TC-050-02): E2E-56 에서 BumpEpoch 를 빼면 기대 12 와 달라 FAIL 이어야 한다.
func TestG12_MutationNoBumpFails(t *testing.T) {
	sc := newG12E2E56().(*g12Scenario)
	orig := sc.exec
	sc.exec = func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
		// BumpEpoch 만 제거한 동일 흐름
		if _, err := g12Call(d, "file_read", g12Read, st.token, 0, "call1"); err != nil {
			return 1, err
		}
		code, _, err := d.CallTool("file_write", g12Write, st.token)
		return code, err
	}
	_ = orig
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()), harness.WithExecutionMode(harness.ModeInProc))
	_ = runner.Register(sc)
	res, err := runner.RunScenario(context.Background(), "E2E-56")
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("mutation (no BumpEpoch) must FAIL")
	}
}

// 변이 검증 (TC-050-03): E2E-60 의 전진을 +6m 으로 줄이면 부모가 살아 있어 재교환이 성공 → FAIL.
func TestG12_MutationShortAdvanceFails(t *testing.T) {
	sc := newG12E2E60().(*g12Scenario)
	sc.exec = func(ctx context.Context, env *harness.SandboxEnvironment, d *SessionDriver, st *g12State) (domain.ExitCode, error) {
		if err := d.AdvanceClock(6 * time.Minute); err != nil {
			return 1, err
		}
		off, err := d.Stack()
		if err != nil {
			return 1, err
		}
		if _, xerr := g12Child(ctx, off, st.parent, 5*time.Minute, "trace-mut"); xerr == nil {
			return 0, harness.Invariantf("re-exchange succeeded")
		}
		return 11, nil
	}
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()), harness.WithExecutionMode(harness.ModeInProc))
	_ = runner.Register(sc)
	res, err := runner.RunScenario(context.Background(), "E2E-60")
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("mutation (+6m) must FAIL")
	}
}
