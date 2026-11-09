// Package state 는 Zone B 권한 상태(.authz-state/public/grants_state.json)의 직렬화 모델 및 동시성 안전한 저장소(Store)를 제공한다.
//
// [저장소 동시성 및 원자성 원칙]
// 1. 단일 파일 잠금 (flock 기반 storage.AtomicFileStore):
//   - 다중 프로세스 및 다중 고루틴 환경에서 상태 파일을 안전하게 공유하기 위해 storage.AtomicFileStore 제네릭 엔진을 활용한다.
//   - 읽기 시 공유 락(syscall.LOCK_SH), 쓰기 시 배타적 락(syscall.LOCK_EX)을 사용한다.
//
// 2. 원자적 교체 (Atomic Rename):
//   - 디스크 쓰기 시 임시 파일에 먼저 기록하고 fsync 후 목적 경로로 atomic rename 하므로, 전원 차단이나 충돌 시에도 파일이 깨지지 않는다.
//
// 3. 방어적 정규화 (ensureStateFields):
//   - JSON 역직렬화 시 Grants, Epochs, Approvals 슬라이스나 맵이 nil 로 풀리지 않도록 빈 인스턴스로 자동 보정한다 (Go typed nil / nil slice 방어).
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
	// Version 은 상태 파일의 스키마 버전 번호다.
	Version int `json:"version"`

	// UpdatedAt 은 마지막 상태 갱신 UTC 시각이다.
	UpdatedAt time.Time `json:"updated_at"`

	// Grants 는 전체 주체에 대한 권한 부여 및 회수 이력 목록이다.
	Grants []domain.Grant `json:"grants"`

	// Epochs 는 주체별 Security Epoch 세대 맵이다.
	Epochs domain.SecurityEpochs `json:"epochs"`

	// Approvals 는 발급되어 유효한 1회성 사람 승인(Approval) 목록이다.
	Approvals []domain.Approval `json:"approvals,omitempty"`
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

// Store 는 Zone B 상태 파일을 동시성 안전하게 다루는 DIP 저장소 인터페이스다.
type Store interface {
	// Load 는 상태 파일을 읽어 스냅샷을 반환한다. 파일이 없으면 초기화된 빈 상태를 반환한다.
	Load() (*GrantsState, error)

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

// ensureStateFields 는 역직렬화 후 슬라이스나 맵이 nil 일 경우 빈 컨테이너로 초기화하여 nil 역참조를 방지한다.
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

// normalizeState 는 디스크 저장 직전에 UpdatedAt 과 버전 필드를 정규화한다.
func (s *FileStore) normalizeState(state *GrantsState) {
	state.UpdatedAt = s.clock.Now().UTC()
	if state.Version == 0 {
		state.Version = 1
	}
	ensureStateFields(state)
}
