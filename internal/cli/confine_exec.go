// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(confine_exec.go)은 OS 수준 프로세스 격리 정책을 적용한 후 대상 바이너리로 교체 실행(exec)하는
// 신뢰 런처(Trusted Launcher) `confine-exec` 서브커맨드를 구현한다.
//
// [보안 아키텍처 및 역할]
// 1. 신뢰 런처 패턴 (Trusted Confinement Launcher):
//    - 문법: authz-harness confine-exec -policy <encoded> -- <target> <args...>
//    - 부모 프로세스가 자식 프로세스에게 부여할 ConfinementPolicy(chroot, rlimit, seccomp 등)를 base64 등으로 인코딩하여 전달.
// 2. 정책 사전 적용 및 원자적 교체 (Pre-Exec Enforcement):
//    - confinement.ApplySelf: 대상 바이너리를 실행하기 전에 현재 런처 프로세스 자체에 보안 감옥(Jail/Sandbox) 정책을 영구 적용.
//    - 정책 적용 전에는 어떠한 외부 파일도 열지 않아 파일 디스크립터 유출이나 부작용을 원천 방지한다.
//    - syscall.Exec: 격리가 완료된 프로세스 이미지 위에서 대상 바이너리를 덮어씌워 실행한다. 성공 시 프로세스 제어권이 넘어가며 결코 반환하지 않는다.
// 3. Fail-Closed 실패 처리:
//    - 정책 디코딩, 대상 바이너리 검색(exec.LookPath), 격리 적용, exec 호출 중 어느 하나라도 실패하면
//      즉시 stderr 에 에러를 기록하고 ExitInternalError 로 종료하며 대상 바이너리는 결코 실행되지 않는다.
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
