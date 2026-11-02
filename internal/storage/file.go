package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WithFileLock 은 lockPath 파일에 대해 flock(how) 배타/공유 락을 획득한 상태에서 fn 을 실행한다.
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

	return nil
}
