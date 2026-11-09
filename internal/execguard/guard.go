// Package execguard 는 exec:run 도구를 위한 코드 고정 화이트리스트(Allow-list) 실행 가드다.
//
// [격리 보안 원칙 및 RCE 방어 불변식]
// 1. 임의 바이너리 실행 원천 차단 (No Arbitrary Path):
//   - 실행 대상은 파일 경로가 아니라 코드에 하드코딩된 논리 ID("echo-safe")로만 지정할 수 있다.
//   - 셸(/bin/sh, bash)을 일체 거치지 않고 exec.CommandContext 로 직접 호출하므로 셸 인젝션이 불가능하다.
//
// 2. 인자 화이트리스트 정규식 검증 (Strict Arg Whitelist):
//   - 인자는 최대 1개, 영숫자·밑줄·대시·점으로 한정된 정규식(^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}$)만 허용한다 (ReasonExecArgRejected).
//
// 3. 무환경 실행 (Clean Environment):
//   - cmd.Env = []string{} 로 설정하여 부모의 환경변수(API 키, 시크릿 등)를 물려받지 않는다 (Zero Leakage).
//
// 4. 출력 바이트 상한 강제 (capWriter):
//   - 자식 프로세스의 stdout 출력이 maxBytes(기본 64KB)를 초과하면 즉시 버퍼링을 중단하고 ReasonToolLimitExceeded 로 거부한다.
package execguard

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"time"

	"authz-harness/internal/domain"
)

const (
	defaultMaxBytes = int64(64 << 10)
	defaultTimeout  = 5 * time.Second
	waitDelay       = 200 * time.Millisecond
)

type spec struct {
	path    string
	maxArgs int
}

// registry 는 코드에 고정된 논리 ID -> 실행 파일 표다.
var registry = map[string]spec{
	"echo-safe": {path: "/bin/echo", maxArgs: 1},
}

var argPattern = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}$`)

// Validate 는 id 와 arg 가 허용 형식인지 프로세스 생성 없이 정적으로 검사한다.
func Validate(id, arg string) error {
	if _, ok := registry[id]; !ok {
		return domain.NewError(domain.ReasonExecNotAllowed, "exec id not registered", nil)
	}
	if arg != "" && !argPattern.MatchString(arg) {
		return domain.NewError(domain.ReasonExecArgRejected, "exec argument rejected", nil)
	}
	return nil
}

// Runner 는 검증된 실행 요청을 격리된 조건으로 실행한다.
type Runner struct {
	dir      string
	maxBytes int64
	timeout  time.Duration
}

// NewRunner 는 작업 디렉터리 dir 과 상한으로 Runner 를 만든다.
func NewRunner(dir string, maxBytes int64, timeout time.Duration) *Runner {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Runner{dir: dir, maxBytes: maxBytes, timeout: timeout}
}

func (r *Runner) buildCmd(ctx context.Context, id, arg string) *exec.Cmd {
	s := registry[id]
	var args []string
	if arg != "" {
		args = append(args, arg)
	}
	cmd := exec.CommandContext(ctx, s.path, args...)
	cmd.Dir = r.dir
	cmd.Env = []string{} // nil 이면 부모 환경을 물려받으므로 명시적 빈 슬라이스 강제
	cmd.Stdin = nil
	cmd.WaitDelay = waitDelay
	return cmd
}

// capWriter 는 limit+1 바이트까지만 보관하고 넘침을 기록한다 (파이프는 계속 비운다).
type capWriter struct {
	buf      []byte
	limit    int64
	exceeded bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.limit + 1 - int64(len(w.buf))
	if room > 0 {
		n := int64(len(p))
		if n > room {
			n = room
		}
		w.buf = append(w.buf, p[:n]...)
	}
	if int64(len(w.buf)) > w.limit {
		w.exceeded = true
	}
	return len(p), nil
}

// Run 은 Validate 후 id 를 실행하고 표준 출력을 반환한다.
func (r *Runner) Run(ctx context.Context, id, arg string) ([]byte, error) {
	if err := Validate(id, arg); err != nil {
		return nil, err
	}
	ctx2, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := r.buildCmd(ctx2, id, arg)
	out := &capWriter{limit: r.maxBytes}
	cmd.Stdout = out
	err := cmd.Run()
	if errors.Is(ctx2.Err(), context.DeadlineExceeded) {
		return nil, domain.NewError(domain.ReasonToolLimitExceeded, "exec timed out", err)
	}
	if out.exceeded {
		return nil, domain.NewError(domain.ReasonToolLimitExceeded, "exec output exceeds byte limit", nil)
	}
	if err != nil {
		return nil, domain.NewError(domain.ReasonInternalError, "exec failed", err)
	}
	return out.buf, nil
}
