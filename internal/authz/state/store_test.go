package state

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/domain"
)

func TestFileStore_Scenario1_EmptyStateInitialization(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")

	store, err := NewFileStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStore 생성 실패: %v", err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("초기 상태 Load 실패: %v", err)
	}

	if state.Version != 1 {
		t.Fatalf("기대 버전 1, 실제 버전 %d", state.Version)
	}
	if len(state.Grants) != 0 {
		t.Fatalf("초기 Grant 목록은 비어있어야 합니다: %d", len(state.Grants))
	}
	if len(state.Epochs) != 0 {
		t.Fatalf("초기 Epoch 맵은 비어있어야 합니다: %d", len(state.Epochs))
	}
}

func TestFileStore_Scenario2_GrantPersistence(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")

	store1, err := NewFileStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStore 1 실패: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	targetGrant := domain.Grant{
		ID:        "grant-550e8400-e29b-41d4-a716-446655440000",
		Subject:   "worker-01",
		Action:    domain.ActionFileRead,
		Resource:  "docs/plan.txt",
		Status:    domain.GrantStatusActive,
		CreatedAt: now,
	}

	err = store1.Update(func(s *GrantsState) error {
		s.Grants = append(s.Grants, targetGrant)
		return nil
	})
	if err != nil {
		t.Fatalf("Update 실패: %v", err)
	}

	// 새 인스턴스로 다시 로드하여 디스크 영속성 검증
	store2, err := NewFileStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStore 2 실패: %v", err)
	}

	loadedState, err := store2.Load()
	if err != nil {
		t.Fatalf("새 인스턴스 Load 실패: %v", err)
	}

	if len(loadedState.Grants) != 1 {
		t.Fatalf("기대 Grant 개수 1, 실제 개수 %d", len(loadedState.Grants))
	}
	g := loadedState.Grants[0]
	if g.ID != targetGrant.ID || g.Subject != targetGrant.Subject ||
		g.Action != targetGrant.Action || g.Resource != targetGrant.Resource ||
		g.Status != targetGrant.Status {
		t.Fatalf("복원된 Grant 불일치: %+v", g)
	}
}

func TestFileStore_Scenario3_EpochBumpPersistence(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")

	store, err := NewFileStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStore 실패: %v", err)
	}

	// worker-01의 Epoch 1 -> 2 증가
	err = store.Update(func(s *GrantsState) error {
		s.Epochs.Bump("worker-01")
		return nil
	})
	if err != nil {
		t.Fatalf("Epoch Bump Update 실패: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load 실패: %v", err)
	}

	if val := loaded.Epochs.Get("worker-01"); val != 2 {
		t.Fatalf("worker-01의 기대 Epoch 2, 실제 %d", val)
	}
}

func TestFileStore_Scenario4_AtomicRenameRollbackOnFailure(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")

	store, err := NewFileStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStore 실패: %v", err)
	}

	// 초기 정상 상태 저장
	initialGrant := domain.Grant{
		ID:        "grant-initial",
		Subject:   "worker-initial",
		Action:    domain.ActionFileRead,
		Resource:  "safe.txt",
		Status:    domain.GrantStatusActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := store.Update(func(s *GrantsState) error {
		s.Grants = append(s.Grants, initialGrant)
		return nil
	}); err != nil {
		t.Fatalf("초기 Update 실패: %v", err)
	}

	// Update 함수 내에서 의도적 에러 발생
	expectedErr := errors.New("simulated business error")
	err = store.Update(func(s *GrantsState) error {
		s.Grants = append(s.Grants, domain.Grant{ID: "grant-corrupted"})
		return expectedErr
	})

	if !errors.Is(err, expectedErr) {
		t.Fatalf("기대 에러 %v, 실제 %v", expectedErr, err)
	}

	// 디스크 상태가 직전 상태를 온전히 보존하는지 검증
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load 실패: %v", err)
	}
	if len(reloaded.Grants) != 1 || reloaded.Grants[0].ID != "grant-initial" {
		t.Fatalf("롤백되지 않고 오염됨: %+v", reloaded.Grants)
	}
}

func TestFileStore_Scenario5_ConcurrentUpdatesRace(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")

	store, err := NewFileStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStore 실패: %v", err)
	}

	numGoroutines := 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		workerID := fmt.Sprintf("worker-%02d", i)
		go func(id string) {
			defer wg.Done()
			err := store.Update(func(s *GrantsState) error {
				s.Grants = append(s.Grants, domain.Grant{
					ID:        "grant-" + id,
					Subject:   id,
					Action:    domain.ActionFileRead,
					Resource:  "docs/" + id + ".txt",
					Status:    domain.GrantStatusActive,
					CreatedAt: time.Now().UTC(),
				})
				s.Epochs.Bump(id)
				return nil
			})
			if err != nil {
				t.Errorf("동시 Update 실패 [%s]: %v", id, err)
			}
		}(workerID)
	}

	wg.Wait()

	finalState, err := store.Load()
	if err != nil {
		t.Fatalf("최종 Load 실패: %v", err)
	}

	if len(finalState.Grants) != numGoroutines {
		t.Fatalf("기대 Grant 수 %d, 실제 %d (Torn Write 의심)", numGoroutines, len(finalState.Grants))
	}
	if len(finalState.Epochs) != numGoroutines {
		t.Fatalf("기대 Epoch 수 %d, 실제 %d", numGoroutines, len(finalState.Epochs))
	}

	// 모든 ID가 빠짐없이 저장되었는지 확인
	recorded := make(map[string]bool)
	for _, g := range finalState.Grants {
		recorded[g.Subject] = true
	}
	for i := 0; i < numGoroutines; i++ {
		expectedID := fmt.Sprintf("worker-%02d", i)
		if !recorded[expectedID] {
			t.Errorf("Grant 누락됨: %s", expectedID)
		}
	}
}

func TestFileStore_InvalidPaths(t *testing.T) {
	_, err := NewFileStore("")
	if err == nil {
		t.Fatal("빈 경로는 에러를 반환해야 합니다")
	}

	store, _ := NewFileStore(filepath.Join(t.TempDir(), "test.json"))
	if err := store.Update(nil); err == nil {
		t.Fatal("nil update fn은 에러를 반환해야 합니다")
	}
}
