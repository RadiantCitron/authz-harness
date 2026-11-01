package jail

import (
	"errors"

	"authz-harness/internal/domain"
)

var (
	// ErrPathViolation 은 경로 검증 실패의 기본 센티넬 에러다.
	ErrPathViolation = errors.New("jail: path violation")

	// ErrPathTraversal 은 상위 디렉터리 순회(..) 또는 외부 절대 경로 지정으로 인한 탈출 시도 에러다.
	ErrPathTraversal = errors.New("jail: path traversal detected")

	// ErrSymlinkEscape 는 심볼릭 링크 해석 결과 격리 경계를 이탈하는 탈출 시도 에러다.
	ErrSymlinkEscape = errors.New("jail: symlink escape detected")

	// ErrInvalidPathCharacters 는 널 바이트 등 유효하지 않은 문자가 경로에 포함된 에러다.
	ErrInvalidPathCharacters = errors.New("jail: invalid path characters")
)

// ReasonFromError 는 jail 에러를 domain.Reason 코드로 변환한다.
func ReasonFromError(err error) domain.Reason {
	if err == nil {
		return domain.ReasonAuthorized
	}
	if errors.Is(err, ErrPathTraversal) {
		return domain.ReasonPathTraversal
	}
	if errors.Is(err, ErrSymlinkEscape) {
		return domain.ReasonSymlinkEscape
	}
	if errors.Is(err, ErrInvalidPathCharacters) {
		return domain.ReasonInvalidPath
	}
	if errors.Is(err, ErrPathViolation) {
		return domain.ReasonPathViolation
	}
	return domain.ReasonPathViolation
}
