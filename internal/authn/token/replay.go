package token

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
	PruneExpired(now time.Time) error
}

// FileReplayLedger 는 파일 락(flock) 및 원자적 쓰기(Atomic Rename)를 보장하는 ReplayLedger 구현체다.
type FileReplayLedger struct {
	mu       sync.Mutex
	filePath string
	clock    domain.Clock
}

// NewFileReplayLedger 는 지정된 경로의 replay_ledger.json 을 다루는 FileReplayLedger 를 생성한다.
func NewFileReplayLedger(filePath string, clock domain.Clock) (*FileReplayLedger, error) {
	if clock == nil {
		clock = domain.RealClock{}
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for replay ledger: %w", err)
	}

	ledger := &FileReplayLedger{
		filePath: filePath,
		clock:    clock,
	}

	// 파일이 존재하지 않으면 기본 빈 원장 생성
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		initial := ReplayData{
			Version:   1,
			UpdatedAt: clock.Now(),
			Entries:   []ReplayEntry{},
		}
		if err := ledger.saveAtomic(&initial); err != nil {
			return nil, fmt.Errorf("failed to initialize replay ledger: %w", err)
		}
	}

	return ledger, nil
}

// CheckAndConsume 는 jti 가 이미 원장에 존재하는지 검사하고, 없으면 등록(소비)한다.
// 동시성 경합 시 파일 락과 프로세스 락으로 상호 배제를 보장한다.
func (l *FileReplayLedger) CheckAndConsume(jti string, expiresAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	lockFile, err := os.OpenFile(l.filePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire file lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	data, err := l.loadUnlocked()
	if err != nil {
		return fmt.Errorf("failed to load replay ledger: %w", err)
	}

	now := l.clock.Now()

	// 1. 이미 존재하는 jti 확인
	for _, entry := range data.Entries {
		if entry.JTI == jti {
			return fmt.Errorf("%w: %s (%s)", ErrReplayDetected, jti, domain.ReasonTokenReplayDetected)
		}
	}

	// 2. 만료된 항목 간단 정리 (Prune on write)
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

	if err := l.saveAtomic(data); err != nil {
		return fmt.Errorf("failed to save replay ledger: %w", err)
	}

	return nil
}

// PruneExpired 는 만료된 jti 항목을 파일에서 완전히 정리한다.
func (l *FileReplayLedger) PruneExpired(now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	lockFile, err := os.OpenFile(l.filePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire file lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	data, err := l.loadUnlocked()
	if err != nil {
		return fmt.Errorf("failed to load replay ledger: %w", err)
	}

	validEntries := make([]ReplayEntry, 0, len(data.Entries))
	for _, entry := range data.Entries {
		if entry.ExpiresAt.After(now) {
			validEntries = append(validEntries, entry)
		}
	}

	data.UpdatedAt = now
	data.Entries = validEntries

	return l.saveAtomic(data)
}

func (l *FileReplayLedger) loadUnlocked() (*ReplayData, error) {
	bytes, err := os.ReadFile(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &ReplayData{
				Version:   1,
				UpdatedAt: l.clock.Now(),
				Entries:   []ReplayEntry{},
			}, nil
		}
		return nil, err
	}

	var data ReplayData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("corrupted replay ledger json: %w", err)
	}
	return &data, nil
}

func (l *FileReplayLedger) saveAtomic(data *ReplayData) error {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal replay data: %w", err)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", l.filePath, time.Now().UnixNano())
	// Zone B 공용 파일 퍼미션 0644 준수
	if err := os.WriteFile(tmpFile, bytes, 0644); err != nil {
		return fmt.Errorf("failed to write tmp replay ledger: %w", err)
	}

	if err := os.Rename(tmpFile, l.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to atomic rename replay ledger: %w", err)
	}

	return nil
}
