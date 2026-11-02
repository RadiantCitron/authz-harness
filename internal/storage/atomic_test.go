package storage_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"authz-harness/internal/storage"
)

type sampleState struct {
	Counter int    `json:"counter"`
	Message string `json:"message"`
}

func TestAtomicFileStore_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "state.json")

	store := storage.NewAtomicFileStore[sampleState](filePath)

	// 초기 읽기 시 파일 없으므로 에러
	val, err := store.Read()
	if err == nil || val != nil {
		t.Fatalf("expected error reading non-existent file, got val=%v, err=%v", val, err)
	}

	// 쓰기
	initial := sampleState{Counter: 42, Message: "hello"}
	if err := store.Write(&initial); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// 읽기 검증
	readVal, err := store.Read()
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if readVal == nil || readVal.Counter != 42 || readVal.Message != "hello" {
		t.Fatalf("unexpected read value: %+v", readVal)
	}
}

func TestAtomicFileStore_Options_And_Default(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "default_state.json")
	customLock := filepath.Join(tmpDir, "custom.lock")

	store := storage.NewAtomicFileStore(
		filePath,
		storage.WithPerm[sampleState](0644),
		storage.WithLockPath[sampleState](customLock),
		storage.WithDefault(func() *sampleState {
			return &sampleState{Counter: 100, Message: "default"}
		}),
	)

	// 파일 미존재 시 default 반환
	val, err := store.Read()
	if err != nil {
		t.Fatalf("expected default value without error, got err=%v", err)
	}
	if val == nil || val.Counter != 100 || val.Message != "default" {
		t.Fatalf("unexpected default value: %+v", val)
	}

	// Update 테스트
	err = store.Update(func(item *sampleState) error {
		item.Counter += 50
		item.Message = "updated"
		return nil
	})
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}

	// 재확인
	updated, err := store.Read()
	if err != nil {
		t.Fatalf("failed to read updated: %v", err)
	}
	if updated.Counter != 150 || updated.Message != "updated" {
		t.Fatalf("unexpected updated value: %+v", updated)
	}

	// 커스텀 락 파일 및 파일 퍼미션 검증
	if _, err := os.Stat(customLock); os.IsNotExist(err) {
		t.Errorf("custom lock file was not created: %s", customLock)
	}
	fi, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Errorf("expected perm 0644, got %v", fi.Mode().Perm())
	}
}

// TC-010-02: 10개 고루틴이 동시 쓰기 수행 시 파일 손상 없이 온전하게 보존
func TestAtomicFileStore_Concurrent(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "concurrent_state.json")

	store := storage.NewAtomicFileStore[sampleState](filePath)

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			item := sampleState{
				Counter: id,
				Message: fmt.Sprintf("goroutine-%d", id),
			}
			if err := store.Write(&item); err != nil {
				t.Errorf("write error in goroutine %d: %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	// 최종 읽기 검증
	finalVal, err := store.Read()
	if err != nil {
		t.Fatalf("failed to read after concurrent writes: %v", err)
	}
	if finalVal == nil {
		t.Fatal("expected non-nil value")
	}

	// 파일 내용이 손상되지 않고 JSON으로 정상 언마샬링되었음을 확인
	rawBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read raw file: %v", err)
	}
	if len(rawBytes) == 0 {
		t.Fatal("file is empty")
	}
}

// T-01: 10개 고루틴이 동시 Update(item.Counter++) 수행 시 정확히 10 증가 보장
func TestAtomicFileStore_Concurrent_Update(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "counter.json")

	store := storage.NewAtomicFileStore(
		filePath,
		storage.WithDefault(func() *sampleState {
			return &sampleState{Counter: 0, Message: "init"}
		}),
	)

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			err := store.Update(func(item *sampleState) error {
				item.Counter++
				return nil
			})
			if err != nil {
				t.Errorf("concurrent update error: %v", err)
			}
		}()
	}

	wg.Wait()

	finalVal, err := store.Read()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if finalVal.Counter != numGoroutines {
		t.Fatalf("expected counter %d, got %d", numGoroutines, finalVal.Counter)
	}
}

func TestAtomicFileStore_Update_ErrorRollback(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "rollback.json")

	store := storage.NewAtomicFileStore(
		filePath,
		storage.WithDefault(func() *sampleState {
			return &sampleState{Counter: 10, Message: "original"}
		}),
	)

	// 초기 상태 저장
	if err := store.Write(&sampleState{Counter: 10, Message: "original"}); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	expectedErr := errors.New("business failure")
	err := store.Update(func(item *sampleState) error {
		item.Counter = 999
		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}

	val, err := store.Read()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if val.Counter != 10 {
		t.Fatalf("expected counter to remain 10, got %d", val.Counter)
	}
}
