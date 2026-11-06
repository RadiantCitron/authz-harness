package harness

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/domain"
)

type trackedProvider struct {
	path    string
	cleaned int
}

func (p *trackedProvider) GetBinaryPath() (string, error) { return p.path, nil }
func (p *trackedProvider) Cleanup() error                 { p.cleaned++; return nil }

func countBinDirs(t *testing.T, tmp string) int {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(tmp, "authz-harness-bin-*"))
	if err != nil {
		t.Fatal(err)
	}
	return len(m)
}

// L1: 러너가 스스로 만든 프로바이더의 임시 폴더는 Close 뒤 남지 않는다.
func TestPlan021_L1_CloseRemovesOwnTempBinaries(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	runner := NewDefaultRunner(WithBaseDir(t.TempDir()))
	_ = runner.Register(&dummyScenario{
		meta: ScenarioMetadata{ID: "L1", Group: "G9",
			Expected: ExpectedAssertion{ExitCode: domain.ExitSuccess, Audit: AuditExpectation{ExpectedStage: NoStageRecord}}},
		execFn: func(ctx context.Context, env *SandboxEnvironment) (domain.ExitCode, error) {
			return domain.ExitSuccess, nil
		},
	})
	if _, err := runner.RunScenario(context.Background(), "L1"); err != nil {
		t.Fatal(err)
	}
	if countBinDirs(t, tmp) == 0 {
		t.Fatal("precondition: runner must have built a temp binary")
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := countBinDirs(t, tmp); n != 0 {
		t.Fatalf("temp binaries left after Close: %d", n)
	}
	// L4: 두 번째 Close 는 오류 없음.
	if err := runner.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// L2: 주입한 프로바이더는 Close 가 건드리지 않는다.
func TestPlan021_L2_CloseKeepsInjectedProviders(t *testing.T) {
	bin, fw := &trackedProvider{path: "/bin/true"}, &trackedProvider{path: "/bin/fw"}
	runner := NewDefaultRunner(WithBaseDir(t.TempDir()), WithBinaryProvider(bin), WithFaultWorkerProvider(fw))
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	if bin.cleaned != 0 || fw.cleaned != 0 {
		t.Fatalf("injected providers must not be cleaned: bin=%d fw=%d", bin.cleaned, fw.cleaned)
	}
}

// L4: 빌드 전 Close, inproc 러너 Close 는 오류 없음.
func TestPlan021_L4_CloseBeforeBuildAndInProc(t *testing.T) {
	if err := NewDefaultRunner(WithBaseDir(t.TempDir())).Close(); err != nil {
		t.Fatalf("before build: %v", err)
	}
	if err := NewDefaultRunner(WithBaseDir(t.TempDir()), WithExecutionMode(ModeInProc)).Close(); err != nil {
		t.Fatalf("inproc: %v", err)
	}
}

// L5: 샌드박스 정리 목록은 Cleanup 에서 폴더 삭제보다 먼저 실행된다.
func TestPlan021_L5_CleanupHooksRunBeforeRemoval(t *testing.T) {
	env := newEnv(t)
	var existedAtHook bool
	env.OnCleanup(func() error {
		_, err := os.Stat(env.RootDir)
		existedAtHook = err == nil
		return nil
	})
	root := env.RootDir
	if err := env.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !existedAtHook {
		t.Fatal("hook must run before the sandbox directory is removed")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("sandbox must be removed: %v", err)
	}
}
