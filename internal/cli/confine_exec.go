package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
)

// RunConfineExec 는 숨김 하위명령 `confine-exec -policy <encoded> -- <target> <args...>` 의 본체다.
// 신뢰 런처로서 정책을 자신에 적용한 뒤 대상으로 exec 한다. 성공하면 반환하지 않는다.
// 어느 단계든 실패하면 stderr 에 사유를 쓰고 종료 코드를 반환하며, 대상은 실행되지 않는다.
// 대상 실행 전에는 어떤 파일도 열지 않는다(정책 적용 전 부작용 금지).
func RunConfineExec(args []string, stderr io.Writer) domain.ExitCode {
	fs := flag.NewFlagSet("confine-exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	policyArg := fs.String("policy", "", "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "confine-exec: %v\n", err)
		return domain.ExitInternalError
	}
	rest := fs.Args()
	if *policyArg == "" || len(rest) == 0 {
		fmt.Fprintln(stderr, "confine-exec: policy and target are required")
		return domain.ExitInternalError
	}
	p, err := confinement.DecodePolicy(*policyArg)
	if err != nil {
		fmt.Fprintf(stderr, "confine-exec: %v\n", err)
		return domain.ExitInternalError
	}
	target, err := exec.LookPath(rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "confine-exec: target not found: %v\n", err)
		return domain.ExitInternalError
	}
	if err := confinement.ApplySelf(p, target); err != nil {
		fmt.Fprintf(stderr, "confine-exec: %v\n", err)
		return domain.ExitInternalError
	}
	err = syscall.Exec(target, rest, os.Environ())
	fmt.Fprintf(stderr, "confine-exec: exec failed: %v\n", err)
	return domain.ExitInternalError
}
