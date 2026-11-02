package storage_test

import (
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
