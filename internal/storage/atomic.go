package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// AtomicFileStore 는 임의의 데이터 타입 T를 파일에 원자적으로 저장하고 동시성 안전하게 읽고 쓰는 제네릭 저장소다.
type AtomicFileStore[T any] struct {
	filePath string
	lockPath string
	perm     os.FileMode
}

// NewAtomicFileStore 는 filePath 경로를 관리하는 AtomicFileStore[T]를 생성한다.
func NewAtomicFileStore[T any](filePath string) *AtomicFileStore[T] {
	return &AtomicFileStore[T]{
		filePath: filePath,
		lockPath: filePath + ".lock",
		perm:     0600,
	}
}

// Read 는 공유 락(LOCK_SH)을 획득한 후 파일 내용을 역직렬화하여 반환한다.
// 파일이 존재하지 않는 경우 nil, os.ErrNotExist를 반환한다.
func (s *AtomicFileStore[T]) Read() (*T, error) {
	var result T
	err := WithFileLock(s.lockPath, syscall.LOCK_SH, func() error {
		data, err := os.ReadFile(s.filePath)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return nil
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("storage: failed to unmarshal json from %s: %w", s.filePath, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// Write 는 배타적 락(LOCK_EX)을 획득한 후 임시 파일 기록 및 원자적 교체(Atomic Rename)를 수행한다.
func (s *AtomicFileStore[T]) Write(data *T) error {
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("storage: failed to create dir %s: %w", dir, err)
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: failed to marshal json: %w", err)
	}

	return WithFileLock(s.lockPath, syscall.LOCK_EX, func() error {
		return AtomicWriteFile(s.filePath, bytes, s.perm)
	})
}
