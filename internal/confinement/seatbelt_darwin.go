//go:build darwin

package confinement

// macOS Seatbelt 어댑터. Policy 를 SBPL 로 바꿔 /usr/bin/sandbox-exec 로 자식을 감싼다.
// sandbox-exec 는 Apple 이 deprecated 로 표기한 도구이나 Confiner 포트 뒤에 있으므로 교체 가능하다
// (060 보증 표에 기록). 폴백은 없다: 적용 불가 시 Available() == false.

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"authz-harness/internal/domain"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

// resolveRealPath 는 심볼릭 링크를 해석한다. 파일이 없으면 부모를 해석한 뒤 이름을 붙인다.
// (macOS 의 /var -> /private/var, /tmp -> /private/tmp 대응)
func resolveRealPath(p string) (string, error) {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	dir, err := resolveRealPath(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(p)), nil
}

func sbplQuote(s string) (string, error) {
	if strings.ContainsAny(s, "\n\r") {
		return "", domain.NewError(domain.ReasonInvalidArguments, "path contains newline", nil)
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`, nil
}

// sbplPath 는 실제 경로를 해석해 filter 표현식을 만든다. 기존 파일이면 literal, 아니면 subpath.
func sbplPath(p string) (string, error) {
	real, err := resolveRealPath(p)
	if err != nil {
		return "", domain.NewError(domain.ReasonInvalidArguments, "cannot resolve path: "+p, err)
	}
	q, err := sbplQuote(real)
	if err != nil {
		return "", err
	}
	if fi, serr := os.Stat(real); serr == nil && !fi.IsDir() {
		return "(literal " + q + ")", nil
	}
	return "(subpath " + q + ")", nil
}

// RenderSeatbeltProfile 은 Policy 를 SBPL 로 변환한다. Seatbelt 는 뒤 규칙이 앞 규칙을 덮는다.
// 실측(2026-11-04): 허용 경로 읽기·쓰기는 루트 메타데이터 규칙 없이도 동작했으나,
// 격리 하 정직 워커의 os.MkdirAll(루트)가 stat 거부를 EEXIST 로 오판해 기동하지 못했다(로드맵 16 / 055).
// 그래서 루트 자체의 file-read-metadata 만 허용한다.
func RenderSeatbeltProfile(p Policy) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	root, err := resolveRealPath(p.ProtectedRoot)
	if err != nil {
		return "", domain.NewError(domain.ReasonInvalidArguments, "cannot resolve protected root", err)
	}
	rootQ, err := sbplQuote(root)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")
	if !p.AllowNetwork {
		b.WriteString("(deny network*)\n")
		for _, port := range uniquePorts(p.AllowConnectPorts) {
			fmt.Fprintf(&b, "(allow network-outbound (remote ip \"localhost:%d\"))\n", port)
		}
	}
	b.WriteString("(deny file-write*)\n")
	b.WriteString("(allow file-write* (literal \"/dev/null\") (literal \"/dev/tty\"))\n")
	for _, w := range p.WritePaths {
		f, err := sbplPath(w)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "(allow file-write* %s)\n", f)
	}
	fmt.Fprintf(&b, "(deny file-read* (subpath %s))\n", rootQ)
	// 루트 디렉터리 자체의 존재 확인(stat)만 허용한다. 정직 워커의 MkdirAll(루트)가 EEXIST 로 오판하지 않게 하며,
	// 루트 안의 파일 내용·목록 읽기는 계속 거부된다.
	fmt.Fprintf(&b, "(allow file-read-metadata (literal %s))\n", rootQ)
	for _, r := range append(append([]string{}, p.ReadPaths...), p.WritePaths...) {
		f, err := sbplPath(r)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "(allow file-read* %s)\n", f)
	}
	return b.String(), nil
}

var (
	seatbeltOnce   sync.Once
	seatbeltUsable bool
)

// CanApplySeatbelt 는 sandbox-exec 적용 가능 여부를 1회 프로브한다(중첩 샌드박스에서는 exit 71).
func CanApplySeatbelt() bool {
	seatbeltOnce.Do(func() {
		out, err := exec.Command(sandboxExecPath, "-p", "(version 1)(allow default)", "/usr/bin/true").CombinedOutput()
		if err != nil {
			slog.Debug("seatbelt probe failed", "err", err, "output", string(out))
			return
		}
		seatbeltUsable = true
	})
	return seatbeltUsable
}

// SeatbeltConfiner 는 macOS 용 Confiner 다.
type SeatbeltConfiner struct{}

func (SeatbeltConfiner) Name() string    { return "darwin-seatbelt" }
func (SeatbeltConfiner) Available() bool { return CanApplySeatbelt() }

// Prepare 는 cmd 를 sandbox-exec 로 감싼다. sandbox-exec 는 대상으로 exec 하므로 PID 가 유지된다.
func (c SeatbeltConfiner) Prepare(cmd *exec.Cmd, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !c.Available() {
		return domain.NewError(domain.ReasonConfinementUnavailable, "seatbelt unavailable (nested sandbox or missing sandbox-exec)", nil)
	}
	profile, err := RenderSeatbeltProfile(p)
	if err != nil {
		return err
	}
	args := []string{"sandbox-exec", "-p", profile, cmd.Path}
	if len(cmd.Args) > 1 {
		args = append(args, cmd.Args[1:]...)
	}
	cmd.Path = sandboxExecPath
	cmd.Args = args
	return nil
}

// Platform 은 darwin 기본 어댑터를 반환한다.
func Platform() Confiner { return SeatbeltConfiner{} }
