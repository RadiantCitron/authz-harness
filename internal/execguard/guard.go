// Package execguard 는 exec:run 도구를 위한 코드 고정 allow-list 실행 가드다.
//
// 실행 파일은 경로가 아니라 코드에 적어 둔 논리 ID 로만 지정한다. 셸을 거치지 않고,
// 인자는 하나 이하이며 형식이 고정되고, 환경변수를 물려받지 않는다.
// 레지스트리를 바깥(플래그·파일)에서 바꾸는 API 는 의도적으로 두지 않는다.
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

// registry 는 코드에 고정된 논리 ID → 실행 파일 표다.
var registry = map[string]spec{
	"echo-safe": {path: "/bin/echo", maxArgs: 1},
}

var argPattern = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}$`)

// Validate 는 id 와 arg 가 허용 형식인지 프로세스 없이 검사한다.
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
	cmd.Env = []string{} // nil 이면 부모 환경을 물려받는다
	cmd.Stdin = nil
	cmd.WaitDelay = waitDelay
	return cmd
}

// capWriter 는 limit+1 바이트까지만 보관하고 넘침을 기록한다(파이프는 계속 비운다).
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
