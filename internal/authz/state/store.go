package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Approvals []domain.Approval     `json:"approvals,omitempty"`
}

// NewEmptyGrantsState 는 주어진 시각을 UpdatedAt 으로 하는 기본 버전 1의 비어있는 GrantsState 구조체를 반환한다.
func NewEmptyGrantsState(now time.Time) *GrantsState {
	return &GrantsState{
		Version:   1,
		UpdatedAt: now.UTC(),
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

// FileStore 는 storage.AtomicFileStore 기반의 파일 시스템 저장소 구현체다.
type FileStore struct {
	store *storage.AtomicFileStore[GrantsState]
	clock domain.Clock
}

// Option 은 FileStore 생성 옵션이다.
type Option func(*FileStore)

// WithClock 은 UpdatedAt 에 쓸 시계를 주입한다 (미주입 시 RealClock).
func WithClock(c domain.Clock) Option {
	return func(s *FileStore) {
		if c != nil {
			s.clock = c
		}
	}
}

// NewFileStore 는 지정된 경로를 관리하는 FileStore 인스턴스를 생성한다.
func NewFileStore(path string, opts ...Option) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("state: path must not be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("state: failed to create directory %s: %w", dir, err)
	}

	fs := &FileStore{clock: domain.RealClock{}}
	for _, o := range opts {
		o(fs)
	}

	fs.store = storage.NewAtomicFileStore[GrantsState](
		path,
		storage.WithPerm[GrantsState](0644),
		storage.WithDefault(func() *GrantsState {
			return NewEmptyGrantsState(fs.clock.Now())
		}),
	)

	return fs, nil
}

// Load 는 공유 락(LOCK_SH) 하에서 상태 파일을 읽어 역직렬화한다.
// 파일이 존재하지 않는 경우 빈 초기 상태를 반환한다.
func (s *FileStore) Load() (*GrantsState, error) {
	state, err := s.store.Read()
	if err != nil {
		return nil, err
	}
	ensureStateFields(state)
	return state, nil
}

// Save 는 배타적 락(LOCK_EX) 하에서 상태를 임시 파일에 기록한 후 atomic rename으로 교체한다.
func (s *FileStore) Save(state *GrantsState) error {
	if state == nil {
		return errors.New("state: state cannot be nil")
	}

	s.normalizeState(state)
	return s.store.Write(state)
}

// Update 는 배타적 락(LOCK_EX) 하에서 최신 상태를 읽고, fn을 적용한 후 원자적으로 디스크에 저장한다.
func (s *FileStore) Update(fn func(state *GrantsState) error) error {
	if fn == nil {
		return errors.New("state: update function cannot be nil")
	}

	return s.store.Update(func(state *GrantsState) error {
		ensureStateFields(state)
		if err := fn(state); err != nil {
			return err
		}
		s.normalizeState(state)
		return nil
	})
}

func ensureStateFields(state *GrantsState) {
	if state.Grants == nil {
		state.Grants = make([]domain.Grant, 0)
	}
	if state.Epochs == nil {
		state.Epochs = make(domain.SecurityEpochs)
	}
	if state.Approvals == nil {
		state.Approvals = make([]domain.Approval, 0)
	}
}

func (s *FileStore) normalizeState(state *GrantsState) {
	state.UpdatedAt = s.clock.Now().UTC()
	if state.Version == 0 {
		state.Version = 1
	}
	ensureStateFields(state)
}
