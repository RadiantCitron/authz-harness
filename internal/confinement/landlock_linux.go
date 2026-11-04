//go:build linux

package confinement

// Linux Landlock 어댑터. landlock_restrict_self 는 호출 프로세스 자신에만 걸리므로,
// 부모는 cmd 를 신뢰 런처(authz-harness confine-exec)로 감싸고 런처가 자신에 적용한 뒤 exec 한다.
// 주의: macOS 호스트에서는 교차 컴파일까지만 검증되었다(런타임 미검증).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"authz-harness/internal/domain"
)

const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	oPath = 0x200000 // O_PATH (syscall 패키지에 미정의)

	createRulesetVersion = 1 << 0
	rulePathBeneath      = 1

	fsExecute    = 1 << 0
	fsWriteFile  = 1 << 1
	fsReadFile   = 1 << 2
	fsReadDir    = 1 << 3
	fsRemoveDir  = 1 << 4
	fsRemoveFile = 1 << 5
	fsMakeChar   = 1 << 6
	fsMakeDir    = 1 << 7
	fsMakeReg    = 1 << 8
	fsMakeSock   = 1 << 9
	fsMakeFifo   = 1 << 10
	fsMakeBlock  = 1 << 11
	fsMakeSym    = 1 << 12
	fsRefer      = 1 << 13 // ABI 2
	fsTruncate   = 1 << 14 // ABI 3
	fsIoctlDev   = 1 << 15 // ABI 5

	netBindTCP    = 1 << 0 // ABI 4
	netConnectTCP = 1 << 1

	sysRuleNetPort = 2 // LANDLOCK_RULE_NET_PORT
)

var systemReadPaths = []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc/self"}

type rulesetAttr struct {
	handledFS  uint64
	handledNet uint64
}

type netPortAttr struct {
	allowed uint64
	port    uint64
}

type pathBeneath struct {
	allowed uint64
	fd      int32
	_       int32
}

var (
	abiOnce sync.Once
	abiVer  int
)

func landlockABI() int {
	abiOnce.Do(func() {
		v, _, e := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, createRulesetVersion)
		if e == 0 {
			abiVer = int(v)
		}
	})
	return abiVer
}

func unavailable(msg string, cause error) error {
	return domain.NewError(domain.ReasonConfinementUnavailable, "confinement", msg, cause)
}

func handledFS(abi int) uint64 {
	m := uint64(fsExecute | fsWriteFile | fsReadFile | fsReadDir | fsRemoveDir | fsRemoveFile |
		fsMakeChar | fsMakeDir | fsMakeReg | fsMakeSock | fsMakeFifo | fsMakeBlock | fsMakeSym)
	if abi >= 2 {
		m |= fsRefer
	}
	if abi >= 3 {
		m |= fsTruncate
	}
	if abi >= 5 {
		m |= fsIoctlDev
	}
	return m
}

// ApplySelf 는 호출 프로세스에 PR_SET_NO_NEW_PRIVS 와 Landlock 규칙을 적용한다.
// execPaths 는 읽기·실행을 추가로 허용할 대상 바이너리 경로다.
func ApplySelf(p Policy, execPaths ...string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	abi := landlockABI()
	if abi < 1 {
		return unavailable("landlock not supported by this kernel", nil)
	}
	if !p.AllowNetwork && abi < 4 {
		return unavailable("landlock ABI < 4 cannot block network", nil)
	}
	root, err := filepath.EvalSymlinks(p.ProtectedRoot)
	if err != nil {
		return unavailable("cannot resolve protected root", err)
	}
	for _, s := range systemReadPaths {
		if root == s || strings.HasPrefix(root, s+"/") {
			return unavailable("protected root is under a system-allowed path; landlock cannot protect it", nil)
		}
	}

	attr := rulesetAttr{handledFS: handledFS(abi)}
	size := uintptr(8)
	if abi >= 4 {
		size = 16
		if !p.AllowNetwork {
			attr.handledNet = netBindTCP | netConnectTCP
		}
	}
	fd, _, e := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), size, 0)
	if e != 0 {
		return unavailable("landlock_create_ruleset failed", e)
	}
	defer syscall.Close(int(fd))

	all := attr.handledFS
	readExec := uint64(fsExecute | fsReadFile | fsReadDir)
	readOnly := uint64(fsReadFile | fsReadDir)
	write := all &^ fsExecute

	add := func(path string, access uint64, mustExist bool) error {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			if !mustExist && os.IsNotExist(err) {
				return nil
			}
			return unavailable("cannot resolve path: "+path, err)
		}
		pfd, err := syscall.Open(real, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			return unavailable("cannot open path: "+real, err)
		}
		defer syscall.Close(pfd)
		if fi, serr := os.Stat(real); serr == nil && !fi.IsDir() {
			access &= fsExecute | fsWriteFile | fsReadFile | fsTruncate | fsIoctlDev // 파일에는 디렉터리 권한 불가
		}
		rule := pathBeneath{allowed: access & all, fd: int32(pfd)}
		if _, _, e := syscall.Syscall6(sysLandlockAddRule, fd, rulePathBeneath, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); e != 0 {
			return unavailable("landlock_add_rule failed: "+real, e)
		}
		return nil
	}
	for _, s := range systemReadPaths {
		if err := add(s, readExec, false); err != nil {
			return err
		}
	}
	for _, x := range execPaths {
		if err := add(x, readExec, true); err != nil {
			return err
		}
	}
	for _, r := range p.ReadPaths {
		if err := add(r, readOnly, true); err != nil {
			return err
		}
	}
	for _, w := range p.WritePaths {
		if err := add(w, write|readOnly, true); err != nil {
			return err
		}
	}
	if err := add("/dev/null", fsReadFile|fsWriteFile|fsTruncate|fsIoctlDev, false); err != nil {
		return err
	}

	// 포트 단위 connect 허용(ABI ≥ 4). bind 는 handledNet 에 있으므로 계속 막힌다.
	for _, r := range landlockNetRules(p) {
		na := netPortAttr{allowed: r.access, port: uint64(r.port)}
		if _, _, e := syscall.Syscall6(sysLandlockAddRule, fd, sysRuleNetPort, uintptr(unsafe.Pointer(&na)), 0, 0, 0); e != 0 {
			return unavailable("landlock_add_rule(net_port) failed", e)
		}
	}

	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0, 0); e != 0 {
		return unavailable("PR_SET_NO_NEW_PRIVS failed", e)
	}
	if _, _, e := syscall.Syscall(sysLandlockRestrictSelf, fd, 0, 0); e != 0 {
		return unavailable("landlock_restrict_self failed", e)
	}
	return nil
}

// LandlockConfiner 는 Linux 용 Confiner 다. LauncherPath 는 authz-harness 바이너리 경로다.
type LandlockConfiner struct {
	LauncherPath string
}

// WithLauncher 는 런처 경로가 주입된 복사본을 반환한다.
func (c LandlockConfiner) WithLauncher(path string) Confiner { c.LauncherPath = path; return c }

func (LandlockConfiner) Name() string    { return "linux-landlock" }
func (LandlockConfiner) Available() bool { return landlockABI() >= 1 }

// Prepare 는 cmd 를 신뢰 런처로 감싼다. 런처는 자신에 Landlock 을 건 뒤 대상으로 exec 한다.
func (c LandlockConfiner) Prepare(cmd *exec.Cmd, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !c.Available() {
		return unavailable("landlock unavailable", nil)
	}
	if c.LauncherPath == "" {
		return unavailable("launcher path not configured", nil)
	}
	enc, err := EncodePolicy(p)
	if err != nil {
		return err
	}
	args := []string{c.LauncherPath, "confine-exec", "-policy", enc, "--", cmd.Path}
	if len(cmd.Args) > 1 {
		args = append(args, cmd.Args[1:]...)
	}
	cmd.Path = c.LauncherPath
	cmd.Args = args
	return nil
}

// Platform 은 linux 기본 어댑터를 반환한다. 런처 경로는 호출자가 LandlockConfiner 로 직접 주입해야 하므로
// 여기서는 LauncherPath 가 빈 값이며, 그 상태의 Prepare 는 16 으로 거부된다.
func Platform() Confiner { return LandlockConfiner{} }
