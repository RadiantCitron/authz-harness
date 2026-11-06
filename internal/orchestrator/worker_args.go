package orchestrator

import "strings"

// WorkerArgs 는 `authz-harness subagent worker` 자식 프로세스의 표준 인자를 만든다.
// -net-allow 는 값이 있을 때만, -verbose 는 verbose 일 때만 넘긴다.
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
