// Package storage 는 다중 프로세스 동시성 제어(flock) 및 정전/충돌에 안전한 원자적 파일 교체(Write-to-Temp & Atomic Rename) 저장소를 제공한다.
//
// [핵심 동시성 및 내구성 보장 원칙]
// 1. Go 제네릭 기반 단일 원자 저장소 (AtomicFileStore[T any]):
//   - 임의의 JSON 직렬화 가능 구조체 T에 대해 공유 락(LOCK_SH) 읽기, 배타 락(LOCK_EX) 쓰기 및 원자적 갱신(Update) 인터페이스를 제공한다.
//
// 2. 가드레일 TC-081-01 storage 일원화 준수:
//   - 전체 비즈니스 계층(authn, keys, authz/state, audit)은 직접 syscall.Flock 을 호출하지 않고 본 storage 패키지를 통해 파일 락을 획득한다.
//
// 3. 디렉터리 동기화 (syncDir / F_FULLFSYNC):
//   - 파일 자체의 fsync 뿐만 아니라 부모 디렉터리 엔트리까지 fsync 하여, OS 충돌이나 급작스러운 전원 차단 시에도 디스크 상의 원자성을 보장한다.
package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// AtomicFileStoreOption 은 AtomicFileStore[T] 설정 함수형 옵션(Functional Option)이다.
type AtomicFileStoreOption[T any] func(*AtomicFileStore[T])

// WithPerm 은 파일 저장 시 적용할 파일 권한을 설정한다 (기본값: 0600).
func WithPerm[T any](perm os.FileMode) AtomicFileStoreOption[T] {
	return func(s *AtomicFileStore[T]) {
		s.perm = perm
	}
}

// WithLockPath 는 기본 <filePath>.lock 대신 별도 지정된 락 파일 경로를 사용하도록 설정한다.
func WithLockPath[T any](lockPath string) AtomicFileStoreOption[T] {
	return func(s *AtomicFileStore[T]) {
		s.lockPath = lockPath
	}
}

// WithDefault 은 파일이 존재하지 않거나 비어있을 때 반환할 기본값 생성 함수를 설정한다.
func WithDefault[T any](defaultFn func() *T) AtomicFileStoreOption[T] {
	return func(s *AtomicFileStore[T]) {
		s.defaultFn = defaultFn
	}
}

// AtomicFileStore 는 임의의 데이터 타입 T를 파일에 원자적으로 저장하고 동시성 안전하게 읽고 쓰는 제네릭 저장소다.
type AtomicFileStore[T any] struct {
	filePath  string
	lockPath  string
	perm      os.FileMode
	defaultFn func() *T
}

// NewAtomicFileStore 는 filePath 경로를 관리하는 AtomicFileStore[T] 인스턴스를 생성한다.
func NewAtomicFileStore[T any](filePath string, opts ...AtomicFileStoreOption[T]) *AtomicFileStore[T] {
	store := &AtomicFileStore[T]{
		filePath: filePath,
		lockPath: filePath + ".lock",
		perm:     0600,
	}
	for _, opt := range opts {
		opt(store)
	}
	return store
}

// Read 는 공유 락(LOCK_SH)을 획득한 후 파일 내용을 역직렬화하여 반환한다.
// 파일이 존재하지 않는 경우 defaultFn이 설정되어 있으면 기본값을 반환하고, 없으면 os.ErrNotExist를 반환한다.
func (s *AtomicFileStore[T]) Read() (*T, error) {
	var result *T
	err := WithFileLock(s.lockPath, syscall.LOCK_SH, func() error {
		loaded, err := s.ReadUnlocked()
		if err != nil {
			return err
		}
		result = loaded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ReadUnlocked 는 이미 락이 획득된 상태에서 파일 내용을 읽어 역직렬화한다.
func (s *AtomicFileStore[T]) ReadUnlocked() (*T, error) {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && s.defaultFn != nil {
			return s.defaultFn(), nil
		}
		return nil, err
	}
	if len(data) == 0 {
		if s.defaultFn != nil {
			return s.defaultFn(), nil
		}
		return nil, nil
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("storage: failed to unmarshal json from %s: %w", s.filePath, err)
	}
	return &result, nil
}

// Write 는 배타적 락(LOCK_EX)을 획득한 후 임시 파일 기록 및 원자적 교체(Atomic Rename)를 수행한다.
func (s *AtomicFileStore[T]) Write(data *T) error {
	return WithFileLock(s.lockPath, syscall.LOCK_EX, func() error {
		return s.WriteUnlocked(data)
	})
}

// WriteUnlocked 는 이미 락이 획득된 상태에서 임시 파일 기록 및 원자적 교체(Atomic Rename)를 수행한다.
func (s *AtomicFileStore[T]) WriteUnlocked(data *T) error {
	if data == nil {
		return errors.New("storage: data cannot be nil")
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("storage: failed to create dir %s: %w", dir, err)
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: failed to marshal json: %w", err)
	}

	return AtomicWriteFile(s.filePath, bytes, s.perm)
}

// Update 는 배타적 락(LOCK_EX)을 획득한 상태에서 기존 데이터를 읽고 fn으로 변경한 후 원자적으로 저장한다.
func (s *AtomicFileStore[T]) Update(fn func(item *T) error) error {
	if fn == nil {
		return errors.New("storage: update function cannot be nil")
	}

	return WithFileLock(s.lockPath, syscall.LOCK_EX, func() error {
		item, err := s.ReadUnlocked()
		if err != nil {
			return err
		}
		if item == nil {
			if s.defaultFn != nil {
				item = s.defaultFn()
			} else {
				var zero T
				item = &zero
			}
		}

		if err := fn(item); err != nil {
			return err
		}

		return s.WriteUnlocked(item)
	})
}
