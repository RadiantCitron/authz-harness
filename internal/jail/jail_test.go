package jail_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"authz-harness/internal/jail"
)

func setupTestWorkspace(t *testing.T) (string, string) {
	t.Helper()

	baseDir := t.TempDir()
	// macOS의 /var -> /private/var 심볼릭 링크 해결
	realBaseDir, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		t.Fatalf("failed to eval symlinks for baseDir: %v", err)
	}

	workspaceDir := filepath.Join(realBaseDir, "workspace")
	outsideDir := filepath.Join(realBaseDir, "outside")

	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatalf("failed to create workspace dir: %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatalf("failed to create outside dir: %v", err)
	}

	return workspaceDir, outsideDir
}

func TestWorkspaceJail_BasicReadWrite(t *testing.T) {
	wsDir, _ := setupTestWorkspace(t)

	j, err := jail.New(wsDir)
	if err != nil {
		t.Fatalf("jail.New failed: %v", err)
	}

	// 1. 단일 파일 쓰기 및 읽기
	filePath := "test.txt"
	content := []byte("hello workspace jail")
	if err := j.WriteFile(filePath, content); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	got, err := j.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("got %q, want %q", got, content)
	}

	// 2. 깊은 중첩 디렉터리 자동 생성 쓰기 및 읽기
	nestedPath := "a/b/c/nested.txt"
	nestedContent := []byte("nested content")
	if err := j.WriteFile(nestedPath, nestedContent); err != nil {
		t.Fatalf("WriteFile nested failed: %v", err)
	}

	gotNested, err := j.ReadFile(nestedPath)
	if err != nil {
		t.Fatalf("ReadFile nested failed: %v", err)
	}
	if !bytes.Equal(gotNested, nestedContent) {
		t.Errorf("got %q, want %q", gotNested, nestedContent)
	}

	// 3. 내부 상대 경로 정규화 (./ 및 ../가 여전히 루트 내부에 머무는 경우)
	relativeSafePath := "a/b/../b/c/nested.txt"
	gotRel, err := j.ReadFile(relativeSafePath)
	if err != nil {
		t.Fatalf("ReadFile relative safe failed: %v", err)
	}
	if !bytes.Equal(gotRel, nestedContent) {
		t.Errorf("got %q, want %q", gotRel, nestedContent)
	}
}

func TestWorkspaceJail_PathTraversalPrevention(t *testing.T) {
	wsDir, outsideDir := setupTestWorkspace(t)

	outsideFile := filepath.Join(outsideDir, "secret.txt")
	outsideContent := []byte("super secret data")
	if err := os.WriteFile(outsideFile, outsideContent, 0644); err != nil {
		t.Fatalf("failed to write outside file: %v", err)
	}

	j, err := jail.New(wsDir)
	if err != nil {
		t.Fatalf("jail.New failed: %v", err)
	}

	traversalCases := []struct {
		name    string
		path    string
		isWrite bool
	}{
		{"상위 탈출 읽기", "../outside/secret.txt", false},
		{"다중 상위 탈출 읽기", "../../../etc/passwd", false},
		{"중첩 속 상위 탈출 읽기", "a/b/../../../../secret.txt", false},
		{"외부 절대경로 읽기", outsideFile, false},
		{"상위 탈출 쓰기", "../outside/hacked.txt", true},
		{"다중 상위 탈출 쓰기", "../../evil.sh", true},
		{"외부 절대경로 쓰기", filepath.Join(outsideDir, "override.txt"), true},
	}

	for _, tc := range traversalCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.isWrite {
				err := j.WriteFile(tc.path, []byte("attack"))
				if err == nil {
					t.Fatalf("expected error for path traversal write %q, got nil", tc.path)
				}
				if !errors.Is(err, jail.ErrPathTraversal) && !errors.Is(err, jail.ErrPathViolation) {
					t.Errorf("expected ErrPathTraversal or ErrPathViolation, got %v", err)
				}
			} else {
				_, err := j.ReadFile(tc.path)
				if err == nil {
					t.Fatalf("expected error for path traversal read %q, got nil", tc.path)
				}
				if !errors.Is(err, jail.ErrPathTraversal) && !errors.Is(err, jail.ErrPathViolation) {
					t.Errorf("expected ErrPathTraversal or ErrPathViolation, got %v", err)
				}
			}
		})
	}
}

func TestWorkspaceJail_PrefixMatchTrap(t *testing.T) {
	// workspaceDir 와 동일한 문자열 접두사를 가지는 workspace-evil 디렉터리 공격
	baseDir := t.TempDir()
	realBase, _ := filepath.EvalSymlinks(baseDir)

	wsDir := filepath.Join(realBase, "workspace")
	evilDir := filepath.Join(realBase, "workspace-evil")

	if err := os.MkdirAll(wsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(evilDir, 0755); err != nil {
		t.Fatal(err)
	}

	evilFile := filepath.Join(evilDir, "target.txt")
	_ = os.WriteFile(evilFile, []byte("evil"), 0644)

	j, err := jail.New(wsDir)
	if err != nil {
		t.Fatal(err)
	}

	// strings.HasPrefix 만 사용했다면 workspace-evil 이 workspace 로 시작하여 통과하는 버그 방어 검증
	_, err = j.ReadFile(evilFile)
	if err == nil {
		t.Fatalf("expected prefix trap path %q to fail, but succeeded", evilFile)
	}
	if !errors.Is(err, jail.ErrPathTraversal) && !errors.Is(err, jail.ErrPathViolation) {
		t.Errorf("expected path violation/traversal, got %v", err)
	}
}

func TestWorkspaceJail_SymlinkEscapePrevention(t *testing.T) {
	wsDir, outsideDir := setupTestWorkspace(t)

	outsideSecret := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideSecret, []byte("classified"), 0644); err != nil {
		t.Fatal(err)
	}

	j, err := jail.New(wsDir)
	if err != nil {
		t.Fatal(err)
	}

	// 1. 심볼릭 링크 파일 읽기 탈출 시도
	symlinkFile := filepath.Join(wsDir, "leak_link.txt")
	if err := os.Symlink(outsideSecret, symlinkFile); err != nil {
		t.Fatal(err)
	}

	_, err = j.ReadFile("leak_link.txt")
	if err == nil {
		t.Fatal("expected reading symlink pointing outside to fail, but succeeded")
	}
	if !errors.Is(err, jail.ErrSymlinkEscape) {
		t.Errorf("expected ErrSymlinkEscape, got %v", err)
	}

	// 2. 조상 디렉터리가 외부를 가리키는 심볼릭 링크인 경우 쓰기 탈출 시도
	symlinkDir := filepath.Join(wsDir, "symlink_dir")
	if err := os.Symlink(outsideDir, symlinkDir); err != nil {
		t.Fatal(err)
	}

	targetUnderSymlink := "symlink_dir/new_evil_file.txt"
	err = j.WriteFile(targetUnderSymlink, []byte("hacked"))
	if err == nil {
		t.Fatal("expected writing under symlink directory to fail, but succeeded")
	}
	if !errors.Is(err, jail.ErrSymlinkEscape) {
		t.Errorf("expected ErrSymlinkEscape, got %v", err)
	}

	// 부작용(Side-effect) 0바이트 검증: outsideDir 에 new_evil_file.txt 가 생성되지 않아야 함
	outsideTarget := filepath.Join(outsideDir, "new_evil_file.txt")
	if _, err := os.Stat(outsideTarget); !os.IsNotExist(err) {
		t.Fatalf("ZERO SIDE-EFFECT VIOLATION: file was created outside workspace at %s", outsideTarget)
	}
}

func TestWorkspaceJail_InvalidCharacters(t *testing.T) {
	wsDir, _ := setupTestWorkspace(t)
	j, err := jail.New(wsDir)
	if err != nil {
		t.Fatal(err)
	}

	// 널 바이트 삽입 경로
	nullPath := "safe.txt\x00.evil"
	_, err = j.ReadFile(nullPath)
	if err == nil {
		t.Fatal("expected null byte path to fail, got nil")
	}
	if !errors.Is(err, jail.ErrInvalidPathCharacters) {
		t.Errorf("expected ErrInvalidPathCharacters, got %v", err)
	}

	err = j.WriteFile(nullPath, []byte("data"))
	if err == nil {
		t.Fatal("expected null byte write to fail, got nil")
	}
	if !errors.Is(err, jail.ErrInvalidPathCharacters) {
		t.Errorf("expected ErrInvalidPathCharacters, got %v", err)
	}

	// 빈 경로
	_, err = j.ReadFile("   ")
	if err == nil {
		t.Fatal("expected empty path to fail, got nil")
	}
}

func TestWorkspaceJail_ZeroSideEffectsOnDeny(t *testing.T) {
	wsDir, outsideDir := setupTestWorkspace(t)
	j, err := jail.New(wsDir)
	if err != nil {
		t.Fatal(err)
	}

	targetOutside := filepath.Join(outsideDir, "leak_target.txt")
	err = j.WriteFile("../outside/leak_target.txt", []byte("bad stuff"))
	if err == nil {
		t.Fatal("expected failure on traversal write")
	}

	if _, err := os.Stat(targetOutside); !os.IsNotExist(err) {
		t.Fatalf("Side effect occurred: %s was created", targetOutside)
	}
}

func TestWorkspaceJail_AtomicWrite_Overwrite(t *testing.T) {
	wsDir, _ := setupTestWorkspace(t)
	j, err := jail.New(wsDir)
	if err != nil {
		t.Fatal(err)
	}

	target := "atomic_target.txt"
	v1 := []byte("version 1 data")
	if err := j.WriteFile(target, v1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	got, err := j.ReadFile(target)
	if err != nil {
		t.Fatalf("read v1 failed: %v", err)
	}
	if !bytes.Equal(got, v1) {
		t.Errorf("got %q, want %q", got, v1)
	}

	// 덮어쓰기 검증 (AtomicWriteFile 정상 교체)
	v2 := []byte("version 2 updated data")
	if err := j.WriteFile(target, v2); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	got2, err := j.ReadFile(target)
	if err != nil {
		t.Fatalf("read v2 failed: %v", err)
	}
	if !bytes.Equal(got2, v2) {
		t.Errorf("got %q, want %q", got2, v2)
	}
}

