package jail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"authz-harness/internal/storage"
)

// Jail 은 지정된 Workspace Root 디렉터리 내에 한정된 안전한 파일 접근 경계를 강제하는 인터페이스다.
type Jail interface {
	// ResolvePath 는 사용자가 입력한 경로(상대/절대)를 검증하고,
	// Workspace Root 내부의 정규화된 안전 물리 절대 경로를 반환한다.
	// 경계를 벗어나거나 유효하지 않은 경로인 경우 ErrPathViolation 및 세부 센티넬 에러를 반환한다.
	ResolvePath(rawPath string, forWrite bool) (string, error)

	// ReadFile 은 Workspace Root 내부의 파일을 안전하게 읽어 바이트 슬라이스로 반환한다.
	ReadFile(rawPath string) ([]byte, error)

	// WriteFile 은 Workspace Root 내부의 파일에 데이터를 안전하게 기록한다.
	// 중간 디렉터리가 없을 경우 0755 퍼미션으로 자동 생성하며, 파일은 0644 퍼미션으로 원자적 기록된다.
	WriteFile(rawPath string, data []byte) error

	// WorkspaceRoot 는 현재 Jail 인스턴스에 바인딩된 기준 루트의 절대 경로를 반환한다.
	WorkspaceRoot() string
}

type workspaceJail struct {
	workspaceRoot string // 정규화되고 심볼릭 링크가 해석된 기준 절대 경로
}

// New 는 주어진 디렉터리 경로를 격리 루트로 삼는 Jail 인스턴스를 생성한다.
// 디렉터리가 존재하지 않거나 디렉터리가 아닌 경우 에러를 반환한다.
func New(workspaceRoot string) (Jail, error) {
	if strings.TrimSpace(workspaceRoot) == "" {
		return nil, fmt.Errorf("%w: workspace root cannot be empty", ErrPathViolation)
	}
	if strings.ContainsRune(workspaceRoot, 0) {
		return nil, fmt.Errorf("%w: null byte in workspace root", ErrInvalidPathCharacters)
	}

	absRoot, err := filepath.Abs(filepath.Clean(workspaceRoot))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to resolve absolute workspace root: %w", ErrPathViolation, err)
	}

	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: workspace root stat failed: %w", ErrPathViolation, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: workspace root must be a directory", ErrPathViolation)
	}

	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to eval symlinks for workspace root: %w", ErrPathViolation, err)
	}

	realRoot = filepath.Clean(realRoot)

	return &workspaceJail{
		workspaceRoot: realRoot,
	}, nil
}

// WorkspaceRoot 는 정규화된 기준 작업 공간의 절대 경로를 반환한다.
func (j *workspaceJail) WorkspaceRoot() string {
	return j.workspaceRoot
}

// isWithinRoot 는 target 경로가 realRoot 내부 또는 동일한 경로인지 filepath.Rel 로 검증한다.
func isWithinRoot(realRoot, target string) bool {
	rel, err := filepath.Rel(realRoot, target)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// ResolvePath 는 사용자가 요청한 경로를 안전하게 해석하여 Workspace Root 내부의 실제 물리 경로를 반환한다.
func (j *workspaceJail) ResolvePath(rawPath string, forWrite bool) (string, error) {
	if strings.TrimSpace(rawPath) == "" {
		return "", fmt.Errorf("%w: path cannot be empty", ErrPathViolation)
	}
	if strings.ContainsRune(rawPath, 0) {
		return "", fmt.Errorf("%w: null byte in path", ErrInvalidPathCharacters)
	}

	var candidate string
	if filepath.IsAbs(rawPath) {
		candidate = filepath.Clean(rawPath)
	} else {
		candidate = filepath.Clean(filepath.Join(j.workspaceRoot, rawPath))
	}

	// 1차 경계 점검: candidate 가 workspaceRoot 하위인지 Rel 로 확인
	if !isWithinRoot(j.workspaceRoot, candidate) {
		return "", fmt.Errorf("%w: path %q escapes root %q", ErrPathTraversal, rawPath, j.workspaceRoot)
	}

	// 심볼릭 링크 및 실제 물리 경로 추적
	if !forWrite {
		// 읽기 요청: 파일이 반드시 존재해야 함
		realTarget, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				return "", err
			}
			return "", fmt.Errorf("%w: failed to eval symlinks for %q: %w", ErrPathViolation, candidate, err)
		}
		realTarget = filepath.Clean(realTarget)

		if !isWithinRoot(j.workspaceRoot, realTarget) {
			return "", fmt.Errorf("%w: symlink targets outside workspace: %q -> %q", ErrSymlinkEscape, rawPath, realTarget)
		}
		return realTarget, nil
	}

	// 쓰기 요청:
	// 파일이 이미 존재하는 경우: EvalSymlinks 로 검증
	info, err := os.Lstat(candidate)
	if err == nil {
		// 존재하는 경우 (심볼릭 링크 또는 일반 파일/디렉토리)
		realTarget, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", fmt.Errorf("%w: failed to eval symlinks for existing file %q: %w", ErrPathViolation, candidate, err)
		}
		realTarget = filepath.Clean(realTarget)

		if !isWithinRoot(j.workspaceRoot, realTarget) {
			return "", fmt.Errorf("%w: file or symlink targets outside workspace: %q -> %q", ErrSymlinkEscape, rawPath, realTarget)
		}
		_ = info
		return realTarget, nil
	}

	if !os.IsNotExist(err) {
		return "", fmt.Errorf("%w: stat failed for %q: %w", ErrPathViolation, candidate, err)
	}

	// 아직 존재하지 않는 파일인 경우:
	// 존재하는 가장 가까운 조상 디렉터리를 역추적하여 조상에 외부 심볼릭 링크가 없는지 확인
	curr := filepath.Dir(candidate)
	var existingAncestor string
	var missingSegments []string

	for {
		ancestorInfo, aErr := os.Lstat(curr)
		if aErr == nil {
			if !ancestorInfo.IsDir() && (ancestorInfo.Mode()&os.ModeSymlink == 0) {
				return "", fmt.Errorf("%w: ancestor path %q is not a directory", ErrPathViolation, curr)
			}
			existingAncestor = curr
			break
		}
		if !os.IsNotExist(aErr) {
			return "", fmt.Errorf("%w: error checking ancestor %q: %w", ErrPathViolation, curr, aErr)
		}

		missingSegments = append([]string{filepath.Base(curr)}, missingSegments...)
		parent := filepath.Dir(curr)
		if parent == curr {
			// 루트까지 도달
			existingAncestor = curr
			break
		}
		curr = parent
	}

	// existingAncestor 의 실제 물리 경로 평가
	realAncestor, err := filepath.EvalSymlinks(existingAncestor)
	if err != nil {
		return "", fmt.Errorf("%w: failed to eval symlinks for ancestor %q: %w", ErrPathViolation, existingAncestor, err)
	}
	realAncestor = filepath.Clean(realAncestor)

	if !isWithinRoot(j.workspaceRoot, realAncestor) {
		return "", fmt.Errorf("%w: ancestor directory symlink targets outside workspace: %q -> %q", ErrSymlinkEscape, existingAncestor, realAncestor)
	}

	// 최종 경로 조합
	parts := append([]string{realAncestor}, missingSegments...)
	parts = append(parts, filepath.Base(candidate))
	finalPath := filepath.Clean(filepath.Join(parts...))

	if !isWithinRoot(j.workspaceRoot, finalPath) {
		return "", fmt.Errorf("%w: composed write path escapes workspace: %q", ErrPathTraversal, finalPath)
	}

	return finalPath, nil
}

// ReadFile 은 파일의 안전 경로를 확인한 후 안전하게 읽는다.
func (j *workspaceJail) ReadFile(rawPath string) ([]byte, error) {
	resolvedPath, err := j.ResolvePath(rawPath, false)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolvedPath)
}

// WriteFile 은 파일의 안전 경로를 확인한 후, 부모 디렉터리를 자동 생성(0755)하고 원자적/안전하게 기록한다.
func (j *workspaceJail) WriteFile(rawPath string, data []byte) error {
	resolvedPath, err := j.ResolvePath(rawPath, true)
	if err != nil {
		return err
	}

	// 부모 디렉터리 생성
	parentDir := filepath.Dir(resolvedPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("%w: failed to create directories: %w", ErrPathViolation, err)
	}

	if err := storage.AtomicWriteFile(resolvedPath, data, 0644); err != nil {
		return fmt.Errorf("%w: failed to write file: %w", ErrPathViolation, err)
	}

	return nil
}
