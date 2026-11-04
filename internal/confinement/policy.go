// Package confinement 는 서브프로세스에 OS 커널 수준 격리를 적용하는 정책과 어댑터 포트를 정의한다.
package confinement

import (
	"path/filepath"
	"strings"

	"authz-harness/internal/domain"
)

const stagePolicy = "confinement_policy"

// Policy 는 허용 목록 기반 격리 정책이다. ProtectedRoot 아래는 목록에 없는 한 읽기·쓰기 모두 거부한다.
//
// 최소 보장 계약(모든 어댑터 공통, 더 엄격한 것은 허용·더 느슨한 것은 불가):
//   - ProtectedRoot 아래에서 ReadPaths·WritePaths 에 속하지 않는 경로는 읽을 수 없다.
//   - WritePaths 밖에는 쓸 수 없다(장치 파일 예외는 어댑터가 정한다).
//   - AllowNetwork 가 false 이면 네트워크 연결·바인드가 실패한다.
type Policy struct {
	Require       bool     // true: 격리를 적용할 수 없으면 스폰 거부(16)
	ProtectedRoot string   // 이 아래는 목록에 없는 한 읽기·쓰기 모두 거부
	ReadPaths     []string // ProtectedRoot 안에서 읽기만 허용할 경로
	WritePaths    []string // 읽기·쓰기를 허용할 경로
	AllowNetwork  bool     // 기본 false: 소켓 연결·바인드 거부
}

// Validate 는 정책의 구조적 유효성을 검사한다. 모호하면 거부한다(Fail-Closed).
func (p Policy) Validate() error {
	if p.ProtectedRoot == "" {
		return domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "protected root must not be empty", nil)
	}
	if !filepath.IsAbs(p.ProtectedRoot) {
		return domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "protected root must be absolute", nil)
	}
	root := filepath.Clean(p.ProtectedRoot)
	for _, rp := range p.ReadPaths {
		if !filepath.IsAbs(rp) {
			return domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "read path must be absolute: "+rp, nil)
		}
		if !within(root, filepath.Clean(rp)) {
			return domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "read path outside protected root: "+rp, nil)
		}
	}
	for _, wp := range p.WritePaths {
		if !filepath.IsAbs(wp) {
			return domain.NewError(domain.ReasonInvalidArguments, stagePolicy, "write path must be absolute: "+wp, nil)
		}
	}
	return nil
}

// within 은 path 가 root 자신이거나 그 아래인지 어휘적으로 판정한다.
func within(root, path string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}

// WorkerPolicy 는 정직한 워커용 정책을 만든다. zone_a 는 어느 목록에도 넣지 않는다.
func WorkerPolicy(root, workspaceDir, zoneBDir, auditPath string) Policy {
	return Policy{
		Require:       true,
		ProtectedRoot: root,
		WritePaths:    []string{workspaceDir, zoneBDir, auditPath, auditPath + ".lock"},
		ReadPaths:     nil,
		AllowNetwork:  false,
	}
}
