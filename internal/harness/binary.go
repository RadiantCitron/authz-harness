package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

// BinaryProvider 는 서브프로세스 실행에 사용할 authz-harness 바이너리 경로를 제공한다.
type BinaryProvider interface {
	GetBinaryPath() (string, error)
}

// CachedBinaryProvider 는 최초 1회 go build 로 바이너리를 컴파일하여 캐싱하는 프로바이더다.
type CachedBinaryProvider struct {
	mu         sync.Mutex
	once       sync.Once
	binaryPath string
	buildErr   error
	tempDir    string
	pkg        string // go build 대상 패키지 경로 (태그 없음)
}

// NewCachedBinaryProvider 는 새 CachedBinaryProvider 를 생성한다.
func NewCachedBinaryProvider() *CachedBinaryProvider {
	return &CachedBinaryProvider{pkg: "./cmd/authz-harness"}
}

// NewFaultWorkerProvider 는 G9 시험 전용 결함 워커 실행 파일을 빌드하는 프로바이더를 생성한다.
func NewFaultWorkerProvider() *CachedBinaryProvider {
	return &CachedBinaryProvider{pkg: "./internal/harness/faultworker"}
}

// locateRepoRoot 는 go.mod 파일이 있는 레포지토리 루트 디렉터리를 탐색한다.
func locateRepoRoot() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get caller info")
	}
	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("failed to locate repo root containing go.mod")
		}
		dir = parent
	}
}

// GetBinaryPath 는 캐시된 바이너리 경로를 반환하며, 아직 빌드되지 않은 경우 1회 빌드한다.
func (p *CachedBinaryProvider) GetBinaryPath() (string, error) {
	p.once.Do(func() {
		repoRoot, err := locateRepoRoot()
		if err != nil {
			p.buildErr = fmt.Errorf("binary provider: %w", err)
			return
		}

		// 1. 임시 디렉터리 생성
		tmpDir, err := os.MkdirTemp("", "authz-harness-bin-*")
		if err != nil {
			p.buildErr = fmt.Errorf("binary provider: failed to create temp dir: %w", err)
			return
		}
		p.tempDir = tmpDir

		targetBin := filepath.Join(tmpDir, filepath.Base(p.pkg))

		// 2. repoRoot 기준 go build 수행
		cmd := exec.Command("go", "build", "-o", targetBin, p.pkg)
		cmd.Dir = repoRoot
		output, err := cmd.CombinedOutput()
		if err != nil {
			p.buildErr = fmt.Errorf("binary provider: go build failed (%v): %s", err, string(output))
			return
		}

		p.binaryPath = targetBin
	})

	return p.binaryPath, p.buildErr
}

// Cleanup 은 생성된 임시 바이너리와 디렉터리를 정리한다.
func (p *CachedBinaryProvider) Cleanup() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.tempDir != "" {
		return os.RemoveAll(p.tempDir)
	}
	return nil
}
