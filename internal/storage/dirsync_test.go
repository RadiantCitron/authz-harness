package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// 계획 008 S1 (W3): rename 뒤 부모 디렉터리 fsync.
// 인수 시나리오는 계획서 AT-S1-01~02 에서 옮겼다.

// AT-S1-01: 존재하지 않는 디렉터리에 대한 syncDir 는 오류를 반환한다.
func TestPlan008_AT_S1_01_SyncDirMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if err := syncDir(missing); err == nil {
		t.Fatalf("syncDir(%q) = nil, want error", missing)
	}
}

// AT-S1-02: 정상 디렉터리에 AtomicWriteFile 은 성공하고, 내용·권한이 그대로이며 임시 파일이 남지 않는다.
func TestPlan008_AT_S1_02_AtomicWriteFileDurableRename(t *testing.T) {
	tests := []struct {
		name string
		perm os.FileMode
	}{
		{"zone-a 0600", 0o600},
		{"zone-b 0644", 0o644},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "state.json")
			data := []byte(`{"v":1}`)

			if err := syncDir(dir); err != nil {
				t.Fatalf("syncDir(existing dir) = %v, want nil", err)
			}
			if err := AtomicWriteFile(dst, data, tc.perm); err != nil {
				t.Fatalf("AtomicWriteFile = %v, want nil", err)
			}

			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(got) != string(data) {
				t.Fatalf("content = %q, want %q", got, data)
			}
			info, err := os.Stat(dst)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if info.Mode().Perm() != tc.perm {
				t.Fatalf("perm = %v, want %v", info.Mode().Perm(), tc.perm)
			}
			leftovers, err := filepath.Glob(filepath.Join(dir, "state.json.tmp.*"))
			if err != nil {
				t.Fatalf("Glob: %v", err)
			}
			if len(leftovers) != 0 {
				t.Fatalf("temp files left behind: %v", leftovers)
			}
		})
	}
}
