package storage_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"authz-harness/internal/storage"
)

type counterState struct {
	Count int `json:"count"`
}

// TC-040-07: 공통 원자적 파일 쓰기 유틸리티 정합성 검증 (동시 50개 고루틴 경쟁)
func TestTC_040_07_ConcurrentAtomicFileUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "counter.json")
	lockPath := filePath + ".lock"

	// 초기 상태 기록
	initial := counterState{Count: 0}
	data, _ := json.Marshal(initial)
	if err := storage.AtomicWriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	numGoroutines := 50
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			err := storage.WithFileLock(lockPath, syscall.LOCK_EX, func() error {
				content, err := os.ReadFile(filePath)
				if err != nil {
					return err
				}

				var st counterState
				if err := json.Unmarshal(content, &st); err != nil {
					return err
				}

				st.Count++

				newData, err := json.Marshal(st)
				if err != nil {
					return err
				}

				return storage.AtomicWriteFile(filePath, newData, 0644)
			})

			if err != nil {
				t.Errorf("update failed: %v", err)
			}
		}()
	}

	wg.Wait()

	finalContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read final file: %v", err)
	}

	var finalState counterState
	if err := json.Unmarshal(finalContent, &finalState); err != nil {
		t.Fatalf("final json corrupted: %v", err)
	}

	if finalState.Count != numGoroutines {
		t.Fatalf("expected count %d, got %d", numGoroutines, finalState.Count)
	}
}
