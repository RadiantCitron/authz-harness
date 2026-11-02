package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

// GrantsState 는 Zone B 상태 파일(.authz-state/public/grants_state.json)의 직렬화 모델이다.
type GrantsState struct {
	Version   int                   `json:"version"`
	UpdatedAt time.Time             `json:"updated_at"`
	Grants    []domain.Grant        `json:"grants"`
	Epochs    domain.SecurityEpochs `json:"epochs"`
}

// NewEmptyGrantsState 는 기본 버전 1을 가진 비어있는 GrantsState 구조체를 반환한다.
func NewEmptyGrantsState() *GrantsState {
	return &GrantsState{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Grants:    make([]domain.Grant, 0),
		Epochs:    make(domain.SecurityEpochs),
	}
}

// Store 는 Zone B 상태 파일을 동시성 안전하게 다루는 저장소 인터페이스다.
type Store interface {
	// Load 는 상태 파일을 읽어 스냅샷을 반환한다. 파일이 없으면 초기화된 빈 상태를 반환한다.
	Load() (*GrantsState, error)

	// Save 는 상태를 배타적 락 하에서 임시 파일에 기록한 후 원자적으로 교체(Atomic Rename)한다.
	Save(state *GrantsState) error

	// Update 는 배타적 락을 획득한 상태에서 상태를 읽고, 변경 함수를 실행한 후 원자적으로 저장한다.
	Update(fn func(state *GrantsState) error) error
}

// FileStore 는 flock 및 Atomic Rename 기반의 파일 시스템 저장소 구현체다.
type FileStore struct {
	path     string
	lockPath string
	mu       sync.Mutex // 단일 프로세스 내 고루틴 간 동기화용 뮤텍스
}

// NewFileStore 는 지정된 경로를 관리하는 FileStore 인스턴스를 생성한다.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("state: path must not be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("state: failed to create directory %s: %w", dir, err)
	}

	return &FileStore{
		path:     path,
		lockPath: path + ".lock",
	}, nil
}

// withFileLock 은 락 파일(.lock)에 대해 OS 수준 flock을 획득한 채 작업을 수행한다.
func (s *FileStore) withFileLock(how int, fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return storage.WithFileLock(s.lockPath, how, fn)
}

// Load 는 공유 락(LOCK_SH) 하에서 상태 파일을 읽어 역직렬화한다.
// 파일이 존재하지 않는 경우 빈 초기 상태를 반환한다.
func (s *FileStore) Load() (*GrantsState, error) {
	var state *GrantsState

	err := s.withFileLock(syscall.LOCK_SH, func() error {
		loaded, err := s.readUnlocked()
		if err != nil {
			return err
		}
		state = loaded
		return nil
	})

	if err != nil {
		return nil, err
	}
	return state, nil
}

// Save 는 배타적 락(LOCK_EX) 하에서 상태를 임시 파일에 기록한 후 atomic rename으로 교체한다.
func (s *FileStore) Save(state *GrantsState) error {
	if state == nil {
		return errors.New("state: state cannot be nil")
	}

	return s.withFileLock(syscall.LOCK_EX, func() error {
		return s.writeUnlocked(state)
	})
}

// Update 는 배타적 락(LOCK_EX) 하에서 최신 상태를 읽고, fn을 적용한 후 원자적으로 디스크에 저장한다.
func (s *FileStore) Update(fn func(state *GrantsState) error) error {
	if fn == nil {
		return errors.New("state: update function cannot be nil")
	}

	return s.withFileLock(syscall.LOCK_EX, func() error {
		state, err := s.readUnlocked()
		if err != nil {
			return err
		}

		if err := fn(state); err != nil {
			return err
		}

		return s.writeUnlocked(state)
	})
}

// readUnlocked 는 락이 이미 획득된 상태에서 내부적으로 파일을 읽는 헬퍼다.
func (s *FileStore) readUnlocked() (*GrantsState, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewEmptyGrantsState(), nil
		}
		return nil, fmt.Errorf("state: failed to read file %s: %w", s.path, err)
	}

	if len(data) == 0 {
		return NewEmptyGrantsState(), nil
	}

	var state GrantsState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("state: failed to unmarshal json from %s: %w", s.path, err)
	}

	if state.Grants == nil {
		state.Grants = make([]domain.Grant, 0)
	}
	if state.Epochs == nil {
		state.Epochs = make(domain.SecurityEpochs)
	}

	return &state, nil
}

// writeUnlocked 는 락이 이미 획득된 상태에서 임시 파일 기록 후 원자적으로 Rename하는 헬퍼다.
func (s *FileStore) writeUnlocked(state *GrantsState) error {
	state.UpdatedAt = time.Now().UTC()
	if state.Version == 0 {
		state.Version = 1
	}
	if state.Grants == nil {
		state.Grants = make([]domain.Grant, 0)
	}
	if state.Epochs == nil {
		state.Epochs = make(domain.SecurityEpochs)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("state: failed to marshal json: %w", err)
	}

	if err := storage.AtomicWriteFile(s.path, data, 0644); err != nil {
		return fmt.Errorf("state: atomic write failed: %w", err)
	}

	return nil
}
