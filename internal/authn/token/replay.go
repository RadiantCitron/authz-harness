package token

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

var (
	// ErrReplayDetected 는 이미 소비된 jti 임을 나타내는 에러다.
	ErrReplayDetected = errors.New("token replay detected: jti already consumed")
)

// ReplayEntry 는 원장에 기록되는 개별 토큰 소비 정보다.
type ReplayEntry struct {
	JTI        string    `json:"jti"`
	ConsumedAt time.Time `json:"consumed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ReplayData 는 replay_ledger.json 에 영속화되는 루트 데이터다.
type ReplayData struct {
	Version   int           `json:"version"`
	UpdatedAt time.Time     `json:"updated_at"`
	Entries   []ReplayEntry `json:"entries"`
}

// ReplayLedger 는 jti 중복 소비 방지 인터페이스다.
type ReplayLedger interface {
	CheckAndConsume(jti string, expiresAt time.Time) error
	// IsConsumed 는 jti 가 이미 소비되었는지 공유 잠금으로 읽기만 한다(소비하지 않는다).
	IsConsumed(jti string) (bool, error)
	PruneExpired(now time.Time) error
}

// FileReplayLedger 는 storage.AtomicFileStore 기반으로 원자적 동기화를 보장하는 ReplayLedger 구현체다.
type FileReplayLedger struct {
	mu    sync.Mutex
	store *storage.AtomicFileStore[ReplayData]
	clock domain.Clock
}

// NewFileReplayLedger 는 지정된 경로의 replay_ledger.json 을 다루는 FileReplayLedger 를 생성한다.
func NewFileReplayLedger(filePath string, clock domain.Clock) (*FileReplayLedger, error) {
	if clock == nil {
		clock = domain.RealClock{}
	}

	store := storage.NewAtomicFileStore(
		filePath,
		storage.WithPerm[ReplayData](0644), // Zone B 공용 파일 퍼미션
		storage.WithDefault(func() *ReplayData {
			return &ReplayData{
				Version:   1,
				UpdatedAt: clock.Now(),
				Entries:   []ReplayEntry{},
			}
		}),
	)

	ledger := &FileReplayLedger{
		store: store,
		clock: clock,
	}

	// 초기 파일 존재하지 않으면 기본 빈 파일 생성 확인
	if _, err := store.Read(); err != nil {
		return nil, fmt.Errorf("failed to initialize replay ledger: %w", err)
	}

	return ledger, nil
}

// CheckAndConsume 는 jti 가 이미 원장에 존재하는지 검사하고, 없으면 등록(소비)한다.
func (l *FileReplayLedger) CheckAndConsume(jti string, expiresAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.store.Update(func(data *ReplayData) error {
		now := l.clock.Now()

		// 1. 이미 존재하는 jti 확인
		for _, entry := range data.Entries {
			if entry.JTI == jti {
				return fmt.Errorf("%w: %s (%s)", ErrReplayDetected, jti, domain.ReasonTokenReplayDetected)
			}
		}

		// 2. 만료된 항목 정리 (Prune on write)
		validEntries := make([]ReplayEntry, 0, len(data.Entries)+1)
		for _, entry := range data.Entries {
			if entry.ExpiresAt.After(now) {
				validEntries = append(validEntries, entry)
			}
		}

		// 3. 신규 jti 소비 등록
		validEntries = append(validEntries, ReplayEntry{
			JTI:        jti,
			ConsumedAt: now,
			ExpiresAt:  expiresAt,
		})

		data.UpdatedAt = now
		data.Entries = validEntries
		return nil
	})
}

// IsConsumed 는 jti 가 원장에 있는지 읽기 전용으로 확인한다.
func (l *FileReplayLedger) IsConsumed(jti string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := l.store.Read()
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil
	}
	for _, e := range data.Entries {
		if e.JTI == jti {
			return true, nil
		}
	}
	return false, nil
}

// PruneExpired 는 만료된 jti 항목을 파일에서 완전히 정리한다.
func (l *FileReplayLedger) PruneExpired(now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.store.Update(func(data *ReplayData) error {
		validEntries := make([]ReplayEntry, 0, len(data.Entries))
		for _, entry := range data.Entries {
			if entry.ExpiresAt.After(now) {
				validEntries = append(validEntries, entry)
			}
		}

		data.UpdatedAt = now
		data.Entries = validEntries
		return nil
	})
}
