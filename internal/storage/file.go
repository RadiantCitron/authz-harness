// Package storage 는 저수준 파일 시스템 동기화 및 flock 락 유틸리티를 제공한다.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WithFileLock 은 lockPath 파일에 대해 flock(how) 배타/공유 락을 획득한 상태에서 fn 을 실행한다.
// 다중 프로세스 간 동기화를 위한 핵심 메커니즘이며, 함수 종료 시 자동으로 언락 및 파일 디스크립터를 정리한다.
func WithFileLock(lockPath string, how int, fn func() error) error {
	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("storage: failed to create dir %s: %w", dir, err)
	}

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("storage: failed to open lock file %s: %w", lockPath, err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), how); err != nil {
		return fmt.Errorf("storage: failed to acquire flock on %s: %w", lockPath, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	return fn()
}

// AtomicWriteFile 은 data 를 임시 파일에 기록하고 Sync 한 뒤 dstPath 로 원자적으로 Rename 한다.
// 충돌이나 정전 시에도 부분 쓰기(Partial Write)나 손상된 파일을 남기지 않도록 보장한다.
func AtomicWriteFile(dstPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("storage: failed to create dir %s: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(dstPath)+".tmp.*")
	if err != nil {
		return fmt.Errorf("storage: failed to create temp file in %s: %w", dir, err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("storage: failed to write temp file %s: %w", tmpName, err)
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("storage: failed to chmod temp file %s: %w", tmpName, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("storage: failed to sync temp file %s: %w", tmpName, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("storage: failed to close temp file %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, dstPath); err != nil {
		return fmt.Errorf("storage: failed to atomic rename %s to %s: %w", tmpName, dstPath, err)
	}

	// 이름 교체(디렉터리 엔트리 변경)는 부모 디렉터리를 fsync 해야 전원 차단 뒤에도 남는다.
	// 실패하면 교체는 이미 일어났지만 내구성을 보장할 수 없으므로 호출자에게 실패를 알린다 (Fail-Closed, 계획 008 D-04).
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("storage: failed to sync dir %s after rename: %w", dir, err)
	}

	return nil
}

// syncDir 는 디렉터리를 열어 fsync 한다. darwin 에서 os.File.Sync 는 F_FULLFSYNC 를 쓴다.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("storage: failed to open dir %s: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("storage: failed to fsync dir %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("storage: failed to close dir %s: %w", dir, err)
	}
	return nil
}
