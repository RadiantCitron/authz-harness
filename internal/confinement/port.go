package confinement

import (
	"os/exec"

	"authz-harness/internal/domain"
)

// Confiner 는 플랫폼별 격리 어댑터 포트다.
//
// Prepare 계약: 먼저 p.Validate() 를 호출해 실패를 그대로 반환하고, 성공하면 cmd.Path·cmd.Args 만
// 래퍼로 바꾼다(Env·Stdin·Stdout·SysProcAttr 불변). 래퍼는 반드시 exec 로 대상이 되어야 하며(fork 금지),
// 적용할 수 없으면 ReasonConfinementUnavailable(16)을 반환한다. 정리 콜백은 두지 않는다.
type Confiner interface {
	Name() string    // "none", "darwin-seatbelt", "linux-landlock"
	Available() bool // 현재 실행 환경에서 실제로 적용 가능한가
	Prepare(cmd *exec.Cmd, p Policy) error
}

// NoopConfiner 는 격리를 적용하지 않는 대조군 전용 어댑터다.
type NoopConfiner struct{}

// Name 은 어댑터 이름을 반환한다.
func (NoopConfiner) Name() string { return "none" }

// Available 은 항상 false 다.
func (NoopConfiner) Available() bool { return false }

// Prepare 는 필수 모드이면 16 으로 거부하고, 아니면 cmd 를 바꾸지 않는다.
func (NoopConfiner) Prepare(_ *exec.Cmd, p Policy) error {
	if p.Require {
		return domain.NewError(domain.ReasonConfinementUnavailable, "no confinement adapter available but confinement is required", nil)
	}
	return nil
}

// LauncherAware 는 신뢰 런처 경로가 필요한 어댑터(Linux)가 구현하는 선택적 인터페이스다.
type LauncherAware interface {
	WithLauncher(path string) Confiner
}

// WithLauncher 는 c 가 LauncherAware 이면 런처 경로를 주입한 복사본을, 아니면 c 를 그대로 반환한다.
func WithLauncher(c Confiner, path string) Confiner {
	if la, ok := c.(LauncherAware); ok {
		return la.WithLauncher(path)
	}
	return c
}
