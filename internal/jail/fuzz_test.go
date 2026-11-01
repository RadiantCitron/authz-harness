package jail_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/jail"
)

func FuzzPathJail(f *testing.F) {
	// 시드 코퍼스 등록
	f.Add("normal.txt", false)
	f.Add("sub/dir/file.txt", true)
	f.Add("../outside.txt", false)
	f.Add("dir/../../outside.txt", true)
	f.Add("/etc/passwd", false)
	f.Add("safe.txt\x00evil.txt", true)
	f.Add("foo/bar/./baz/../../qux.txt", false)
	f.Add("..", true)
	f.Add(".", false)
	f.Add("", true)
	f.Add(strings.Repeat("a/", 200)+"file.txt", false)
	f.Add("%2e%2e%2fetc%2fpasswd", true)

	baseDir := f.TempDir()
	realBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		f.Fatalf("eval symlinks baseDir failed: %v", err)
	}
	wsDir := filepath.Join(realBase, "workspace")
	if err := os.MkdirAll(wsDir, 0755); err != nil {
		f.Fatalf("create wsDir failed: %v", err)
	}

	j, err := jail.New(wsDir)
	if err != nil {
		f.Fatalf("jail.New failed: %v", err)
	}

	f.Fuzz(func(t *testing.T, rawPath string, forWrite bool) {
		// 불변식 1: ResolvePath 는 절대 크래시/패닉을 발생시키지 않는다.
		resolved, err := j.ResolvePath(rawPath, forWrite)
		if err != nil {
			// 에러가 반환된 경우 resolved 는 비어있어야 함
			if resolved != "" {
				t.Fatalf("expected empty resolved path on error, got %q", resolved)
			}
			return
		}

		// 불변식 2: ResolvePath 가 성공한 경우 반환된 경로는 반드시 workspaceRoot 내부에 존재해야 한다.
		rel, err := filepath.Rel(j.WorkspaceRoot(), resolved)
		if err != nil {
			t.Fatalf("filepath.Rel failed for valid path: %v", err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("INVARIANT VIOLATION: resolved path %q escapes root %q (rel: %q)", resolved, j.WorkspaceRoot(), rel)
		}
	})
}
