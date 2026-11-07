package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/orchestrator"
)

// workerSpawnerConfig 는 CLI(orchestrate, mcp)에서 격리 서브프로세스 스포너를 조립하기 위한 명세다.
type workerSpawnerConfig struct {
	WorkerBin     string
	AuditPath     string
	WorkspacePath string
	StatePath     string
	PubJWKSPath   string
	ReplayPath    string
	NetAllow      string
	Verbose       bool
	Timeout       time.Duration
}

// buildWorkerSpawner 는 감사 로그 스택 초기화, 바이너리 위치 확인, 파일 경로의 절대 경로 정규화,
// WorkerArgs 생성 및 SubprocessSpawner 조립을 일원화하여 수행한다.
func buildWorkerSpawner(cfg workerSpawnerConfig, errOut io.Writer) (*orchestrator.SubprocessSpawner, *app.AppStack, error) {
	// 1. 감사 로그 기록기 초기화 (합성 루트 VerifyOnly 모드)
	stack, err := app.BuildStack(app.AppConfig{AuditPath: cfg.AuditPath, VerifyOnly: true})
	if err != nil {
		fmt.Fprintf(errOut, "Error: failed to init audit writer: %v\n", err)
		return nil, nil, err
	}

	// 2. 바이너리 결정
	binPath := cfg.WorkerBin
	if binPath == "" {
		exe, err := os.Executable()
		if err != nil {
			stack.Close()
			fmt.Fprintf(errOut, "Error: failed to get executable path: %v\n", err)
			return nil, nil, err
		}
		binPath = exe
	}

	// 3. 상대 경로 파일인 경우 절대 경로로 정규화 (하위 프로세스 환경 차이 방지)
	absState, err := filepath.Abs(cfg.StatePath)
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to resolve state path: %v\n", err)
		return nil, nil, err
	}
	absPubJWKS, err := filepath.Abs(cfg.PubJWKSPath)
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to resolve pub jwks path: %v\n", err)
		return nil, nil, err
	}
	absReplay, err := filepath.Abs(cfg.ReplayPath)
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to resolve replay path: %v\n", err)
		return nil, nil, err
	}
	absAudit, err := filepath.Abs(cfg.AuditPath)
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to resolve audit path: %v\n", err)
		return nil, nil, err
	}
	absWorkspace, err := filepath.Abs(cfg.WorkspacePath)
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to resolve workspace path: %v\n", err)
		return nil, nil, err
	}

	childArgs := orchestrator.WorkerArgs(absWorkspace, absState, absPubJWKS, absReplay, absAudit, cfg.NetAllow, cfg.Verbose)

	// 4. Spawner 구성
	spawner, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath: binPath,
		Args:       childArgs,
		Limits:     orchestrator.Limits{Timeout: cfg.Timeout},
		Audit:      stack.AuditWriter,
	})
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to create spawner: %v\n", err)
		return nil, nil, err
	}

	return spawner, stack, nil
}
