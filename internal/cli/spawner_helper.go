// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(spawner_helper.go)은 orchestrate 및 mcp 서브커맨드에서 격리된 자식 워커(Subprocess)를
// 안전하게 기동하기 위해 공통으로 사용하는 헬퍼 함수 및 설정을 제공한다.
//
// [보안 아키텍처 및 역할]
// 1. 경로 정규화 및 상대 경로 오염 방지 (Absolute Path Canonicalization):
//    - 부모와 자식 프로세스의 작업 디렉터리가 서로 다를 수 있으므로, 상태 파일, 공개키, Replay 원장, 감사 로그,
//      워크스페이스 경로를 반드시 filepath.Abs 로 정규화하여 전달한다.
// 2. 단일 합성 루트 연동 및 자원 누수 방지 (Stack Integration):
//    - app.BuildStack 을 VerifyOnly 모드로 기동하여 스포너에 필요한 AuditWriter 를 확보하고,
//      실패 시 즉시 stack.Close() 를 호출하여 파일 락 및 디스크립터 누수를 방지한다.
// 3. 자식 프로세스 표준 인자 조립 (Standard Worker CLI Args):
//    - orchestrator.WorkerArgs 를 통해 일관된 CLI 플래그(-workspace, -state-file, -pub-jwks-file, -replay-file, -audit-file, -net-allow 등)를 생성한다.
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/confinement"
	"authz-harness/internal/orchestrator"
)

// workerSpawnerConfig 는 CLI(orchestrate, mcp)에서 격리 서브프로세스 스포너를 조립하기 위한 명세다.
type workerSpawnerConfig struct {
	WorkerBin     string        // 워커 바이너리 경로 (생략 시 os.Executable() 자동 탐색)
	AuditPath     string        // 감사 로그 파일 경로
	WorkspacePath string        // 격리 워크스페이스 디렉터리 경로
	StatePath     string        // Zone B 상태 파일 경로
	PubJWKSPath   string        // Zone B 공개 키(JWKS) 경로
	ReplayPath    string        // Replay 방지 원장 경로
	NetAllow      string        // net:fetch 허용 호스트 목록 (쉼표 구분)
	Verbose       bool          // 디버그 로깅 활성화 여부
	Timeout       time.Duration // 서브프로세스 실행 제한 시간

	// Confine 이 true 면 워커를 OS 커널 격리(Seatbelt/Landlock) 아래에서 기동한다.
	// 격리를 적용할 수 없는 환경에서는 워커를 띄우지 않고 거부한다 (종료 코드 16).
	Confine     bool
	PrivKeyPath string // Zone A 개인키 경로. 격리 정책의 보호 루트를 계산하는 데만 쓰며 워커에는 넘기지 않는다.
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
	spawnCfg := orchestrator.SpawnConfig{
		BinaryPath: binPath,
		Args:       childArgs,
		Limits:     orchestrator.Limits{Timeout: cfg.Timeout},
		Audit:      stack.AuditWriter,
	}
	if cfg.Confine {
		absPriv, err := filepath.Abs(cfg.PrivKeyPath)
		if err != nil {
			stack.Close()
			fmt.Fprintf(errOut, "Error: failed to resolve priv key path: %v\n", err)
			return nil, nil, err
		}
		pol, err := buildConfinementPolicy(absPriv, absState, absPubJWKS, absReplay, absWorkspace, absAudit, cfg.NetAllow)
		if err != nil {
			stack.Close()
			fmt.Fprintf(errOut, "Error: cannot build confinement policy: %v\n", err)
			return nil, nil, err
		}
		spawnCfg.Confiner = confinement.WithLauncher(confinement.Platform(), binPath)
		spawnCfg.Confinement = pol
	}
	spawner, err := orchestrator.NewSubprocessSpawner(spawnCfg)
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to create spawner: %v\n", err)
		return nil, nil, err
	}

	return spawner, stack, nil
}

// buildMultiHopSpawner 는 Zone A 개인키를 포함한 합성 루트 스택 초기화, 바이너리 위치 확인,
// 파일 경로 절대경로 정규화, 격리 정책 조립 및 MultiHopSpawner 생성을 일원화하여 수행한다.
func buildMultiHopSpawner(cfg workerSpawnerConfig, errOut io.Writer) (*orchestrator.MultiHopSpawner, *app.AppStack, error) {
	// 1. Zone A 개인키를 포함한 전체 스택 초기화 (토큰 교환기 ExchangeService 및 부모 PEP 확보)
	stack, err := app.BuildStack(app.AppConfig{
		StatePath:    cfg.StatePath,
		PrivKeyPath:  cfg.PrivKeyPath,
		PubJWKSPath:  cfg.PubJWKSPath,
		ReplayPath:   cfg.ReplayPath,
		AuditPath:    cfg.AuditPath,
		WorkspaceDir: cfg.WorkspacePath,
	})
	if err != nil {
		fmt.Fprintf(errOut, "Error: failed to init app stack for multi-hop: %v\n", err)
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

	// 3. 상대 경로 정규화
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

	hopCfg := orchestrator.MultiHopConfig{
		BinaryPath:   binPath,
		WorkspaceDir: absWorkspace,
		StatePath:    absState,
		PubJWKSPath:  absPubJWKS,
		ReplayPath:   absReplay,
		AuditPath:    absAudit,
		Audit:        stack.AuditWriter,
		Gateway:      stack.PEP,
		Limits:       orchestrator.Limits{Timeout: cfg.Timeout},
	}

	if cfg.Confine {
		absPriv, err := filepath.Abs(cfg.PrivKeyPath)
		if err != nil {
			stack.Close()
			fmt.Fprintf(errOut, "Error: failed to resolve priv key path: %v\n", err)
			return nil, nil, err
		}
		pol, err := buildConfinementPolicy(absPriv, absState, absPubJWKS, absReplay, absWorkspace, absAudit, cfg.NetAllow)
		if err != nil {
			stack.Close()
			fmt.Fprintf(errOut, "Error: cannot build confinement policy: %v\n", err)
			return nil, nil, err
		}
		hopCfg.Confiner = confinement.WithLauncher(confinement.Platform(), binPath)
		hopCfg.Confinement = pol
	}

	spawner, err := orchestrator.NewMultiHopSpawner(hopCfg)
	if err != nil {
		stack.Close()
		fmt.Fprintf(errOut, "Error: failed to create multi-hop spawner: %v\n", err)
		return nil, nil, err
	}

	return spawner, stack, nil
}
