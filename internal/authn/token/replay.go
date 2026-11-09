// Package token 은 JWT jti 리플레이 방지 장부(Replay Ledger) 및 중복 소비 차단 기능을 제공한다.
//
// [리플레이 방지 아키텍처와 원자적 영속화]
// 1. 단일 jti 1회성 소비 강제 (Single Use / Nonce):
//    - 동일한 jti 를 가진 토큰이 재인입되면 ReasonTokenReplayDetected 로 즉시 차단(Fail-Closed)한다.
// 2. Zone B 공유 파일 영속화:
//    - replay_ledger.json 은 0644 권한으로 Zone B 에 안전하게 저장되며,
//      storage.AtomicFileStore 의 배타 락(flock)을 통해 동시성 경합 없이 원자적으로 갱신된다.
// 3. 쓰기 시 만료 항목 자동 정리 (Prune on Write):
//    - 신규 jti 소비 시 현재 시각(now) 기준으로 이미 만료된(ExpiresAt < now) 항목을 메모리에서 걸러내어
//      장부 파일의 크기가 무한히 증가하는 메모리/디스크 누수를 방지한다.
package token

import (
	"errors"
	"fmt"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

var (
	// ErrReplayDetected 는 이미 소비된 jti 임을 나타내는 에러다.
	ErrReplayDetected = errors.New("token replay detected: jti already consumed")
)

// ReplayEntry 는 리플레이 장부에 영속화되는 개별 토큰 소비 이력 엔트리다.
type ReplayEntry struct {
	// JTI 는 소비된 토큰의 전역 고유 식별자다.
	JTI string `json:"jti"`

	// ConsumedAt 은 토큰이 최초 소비된 시각(UTC)이다.
	ConsumedAt time.Time `json:"consumed_at"`

	// ExpiresAt 은 토큰 자체의 만료 시각(exp)이다. 장부 프루닝(Pruning)의 기준이 된다.
	ExpiresAt time.Time `json:"expires_at"`
}

// ReplayData 는 replay_ledger.json 에 기록되는 루트 JSON 구조체다.
type ReplayData struct {
	Version   int           `json:"version"`
	UpdatedAt time.Time     `json:"updated_at"`
	Entries   []ReplayEntry `json:"entries"`
}

// ReplayLedger 는 jti 중복 소비 방지를 위한 도메인 포트 인터페이스(DIP)다.
type ReplayLedger interface {
	// CheckAndConsume 는 jti 가 이미 존재하는지 원자적으로 검사하고, 없으면 등록(소비)한다.
	CheckAndConsume(jti string, expiresAt time.Time) error

	// IsConsumed 는 jti 가 이미 소비되었는지 공유 잠금으로 읽기만 한다 (소비 상태를 변경하지 않음).
	IsConsumed(jti string) (bool, error)
}

// FileReplayLedger 는 storage.AtomicFileStore 기반으로 원자적 동기화를 보장하는 ReplayLedger 구현체다.
type FileReplayLedger struct {
	store *storage.AtomicFileStore[ReplayData]
	clock domain.Clock
}

// NewFileReplayLedger 는 지정된 경로의 replay_ledger.json 을 다루는 FileReplayLedger 인스턴스를 생성한다.
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
	return l.store.Update(func(data *ReplayData) error {
		now := l.clock.Now()

		// 1. 이미 존재하는 jti 확인 (리플레이 공격 감지)
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
	data, err := l.store.Read()
	if err != nil {
		return false, err
	}
	for _, e := range data.Entries {
		if e.JTI == jti {
			return true, nil
		}
	}
	return false, nil
}
