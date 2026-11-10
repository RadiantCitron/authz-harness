// Package confinement 는 서브프로세스에 OS 커널 수준 격리를 적용하는 정책과 어댑터 포트를 정의한다.
// 본 파일(builder.go)은 CLI 경로(파일 시스템 경로들)로부터 정직한 워커용 커널 격리 정책을
// 안전하게 계산·조립하는 순수 함수를 제공한다.
//
// [정책 계산 원칙 및 보안 불변식]
//  1. 보호 루트(ProtectedRoot)는 Zone A(개인키 폴더)와 Zone B(상태 폴더)의 공통 조상 폴더다.
//     기본 배치(.authz-state/private, .authz-state/public)에서는 .authz-state 가 된다.
//  2. 두 폴더의 공통 조상이 파일 시스템 루트(/)뿐이면 정책을 만들지 않고 거부한다 (Fail-Closed).
//     시스템 전체를 보호 루트로 삼으면 워커가 자신의 실행 파일조차 읽지 못한다.
//  3. 쓰기 허용 목록은 WorkerPolicy 가 정한 것(워크스페이스, Zone B 폴더, 감사 파일)에,
//     공개키·리플레이 원장이 다른 폴더에 있는 경우 그 폴더를 더한 것이다. Zone A 는 어느 목록에도 넣지 않는다.
//  4. 네트워크는 기본 거부이고, net:fetch 허용 목록(host:port)에 적힌 포트만 연다.
//     포트가 없거나 범위를 벗어난 항목은 모호하므로 거부한다.
package confinement

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"authz-harness/internal/domain"
)

// CommonAncestor 는 두 절대 경로의 공통 조상 폴더를 반환한다. 공통 조상이 없으면 파일 시스템 루트("/")다.
func CommonAncestor(a, b string) string {
	sep := string(filepath.Separator)
	ap := strings.Split(filepath.Clean(a), sep)
	bp := strings.Split(filepath.Clean(b), sep)
	var common []string
	for i := 0; i < len(ap) && i < len(bp); i++ {
		if ap[i] != bp[i] {
			break
		}
		common = append(common, ap[i])
	}
	root := strings.Join(common, sep)
	if root == "" {
		return sep
	}
	return root
}

// ParseConnectPorts 는 쉼표로 구분된 host:port 목록에서 포트 번호만 중복 없이 뽑는다.
// 비어 있는 입력은 포트 없음(nil)이다. 포트가 없거나 범위를 벗어난 항목은 오류다.
func ParseConnectPorts(netAllow string) ([]int, error) {
	var ports []int
	seen := make(map[int]struct{})
	for _, entry := range strings.Split(netAllow, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, portStr, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, domain.NewError(domain.ReasonInvalidArguments, "confine: net-allow entry must be host:port: "+entry, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, domain.NewError(domain.ReasonInvalidArguments, "confine: net-allow port out of range: "+entry, err)
		}
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

// BuildWorkerPolicy 는 절대 경로들로부터 워커용 격리 정책을 계산한다.
// 모든 경로 인자는 호출자가 절대 경로로 정규화해서 넘겨야 한다.
func BuildWorkerPolicy(privKeyPath, statePath, pubJWKSPath, replayPath, workspaceDir, auditPath, netAllow string) (Policy, error) {
	if !filepath.IsAbs(privKeyPath) || !filepath.IsAbs(statePath) {
		return Policy{}, domain.NewError(domain.ReasonInvalidArguments, "confine: priv-key-file and state-file must resolve to absolute paths", nil)
	}
	zoneADir := filepath.Dir(privKeyPath)
	zoneBDir := filepath.Dir(statePath)

	root := CommonAncestor(zoneADir, zoneBDir)
	if root == string(filepath.Separator) {
		return Policy{}, domain.NewError(domain.ReasonInvalidArguments,
			"confine: zone A ("+zoneADir+") and zone B ("+zoneBDir+") share no folder except the filesystem root; refusing to protect the whole filesystem", nil)
	}

	pol := WorkerPolicy(root, workspaceDir, zoneBDir, auditPath)
	for _, extra := range []string{filepath.Dir(pubJWKSPath), filepath.Dir(replayPath)} {
		if extra == "" || extra == "." {
			continue
		}
		pol.WritePaths = appendUnique(pol.WritePaths, extra)
	}

	ports, err := ParseConnectPorts(netAllow)
	if err != nil {
		return Policy{}, err
	}
	pol.AllowConnectPorts = ports

	if err := pol.Validate(); err != nil {
		return Policy{}, err
	}
	return pol, nil
}

// appendUnique 는 값이 목록에 없을 때만 덧붙인다.
func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
