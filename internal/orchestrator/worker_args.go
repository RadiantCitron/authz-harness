// Package orchestrator 는 subagent worker 자식 프로세스 실행 인자 빌더를 제공한다.
package orchestrator

import "strings"

// WorkerArgs 는 `authz-harness subagent worker` 자식 프로세스의 표준 인자를 만든다.
// -net-allow 는 값이 있을 때만, -verbose 는 verbose 일 때만 넘긴다.
// [보안 의도]: -net-allow 를 넘기지 않는 호출부(orchestrate, multi_hop, 시나리오)의 워커는 net:fetch 를 전부 거부한다(Fail-Closed).
// 커맨드라인 인자(argv)에는 절대 Bearer 토큰이나 비밀값을 포함하지 않는다 (Zero Leakage).
func WorkerArgs(workspace, stateFile, pubJWKS, replay, auditFile, netAllow string, verbose bool) []string {
	args := []string{
		"subagent", "worker",
		"-workspace", workspace,
		"-state-file", stateFile,
		"-pub-jwks-file", pubJWKS,
		"-replay-file", replay,
		"-audit-file", auditFile,
	}
	if strings.TrimSpace(netAllow) != "" {
		args = append(args, "-net-allow", netAllow)
	}
	if verbose {
		args = append(args, "-verbose")
	}
	return args
}
