// Package cli 는 authz-harness 의 명령줄 인터페이스(CLI) 하위 명령어 러너들을 제공한다.
// 본 파일(confine_config.go)은 `orchestrate spawn -confine` 과 `mcp serve -confine` 이 켜는 OS 커널 격리의
// 정책을 CLI 경로(파일 경로들)로부터 계산하는 순수 함수를 제공한다.
//
// [왜 필요한가]
// 로드맵 11 은 SpawnConfig 의 격리 필드 영값을 「꺼짐」으로 정해 평소 CLI 실행의 동작을 바꾸지 않았다.
// 이 파일은 사용자가 `-confine` 플래그로 명시했을 때만 그 필드를 채우는 계산을 맡는다.
//
// [정책 계산 원칙]
//  1. 보호 루트(ProtectedRoot)는 Zone A(개인키 폴더)와 Zone B(상태 폴더)의 공통 조상 폴더다.
//     기본 배치(.authz-state/private, .authz-state/public)에서는 .authz-state 가 된다.
//  2. 두 폴더의 공통 조상이 파일 시스템 루트(/)뿐이면 정책을 만들지 않고 거부한다 (Fail-Closed).
//     시스템 전체를 보호 루트로 삼으면 워커가 자신의 실행 파일조차 읽지 못한다.
//  3. 쓰기 허용 목록은 confinement.WorkerPolicy 가 정한 것(워크스페이스, Zone B 폴더, 감사 파일)에,
//     공개키·리플레이 원장이 다른 폴더에 있는 경우 그 폴더를 더한 것이다. Zone A 는 어느 목록에도 넣지 않는다.
//  4. 네트워크는 기본 거부이고, net:fetch 허용 목록(host:port)에 적힌 포트만 연다.
//     포트가 없거나 잘못된 항목은 모호하므로 거부한다.
package cli

import (
	"authz-harness/internal/confinement"
)

// commonAncestor 는 두 절대 경로의 공통 조상 폴더를 반환한다.
// 실제 계산은 confinement.CommonAncestor 에 위임한다 (계획 050 공용화).
func commonAncestor(a, b string) string {
	return confinement.CommonAncestor(a, b)
}

// parseConnectPorts 는 쉼표로 구분된 host:port 목록에서 포트 번호만 중복 없이 뽑는다.
// 실제 파싱은 confinement.ParseConnectPorts 에 위임한다 (계획 050 공용화).
func parseConnectPorts(netAllow string) ([]int, error) {
	return confinement.ParseConnectPorts(netAllow)
}

// buildConfinementPolicy 는 절대 경로들로부터 워커용 격리 정책을 계산한다.
// 실제 정책 계산은 confinement.BuildWorkerPolicy 에 위임한다 (계획 050 공용화).
func buildConfinementPolicy(privKeyPath, statePath, pubJWKSPath, replayPath, workspaceDir, auditPath, netAllow string) (confinement.Policy, error) {
	return confinement.BuildWorkerPolicy(privKeyPath, statePath, pubJWKSPath, replayPath, workspaceDir, auditPath, netAllow)
}
