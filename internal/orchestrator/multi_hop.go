// Package orchestrator 는 루트 오케스트레이터로부터 중간 리드, 하위 워커로 이어지는 다단계 위임(Multi-hop) 실행 엔진을 제공한다.
//
// [다단계 위임 아키텍처 및 계보 추적 불변식]
// 1. 2-Hop 토큰 축소 위임 연쇄:
//   - Hop 1: 루트 토큰(Depth 0) -> 중간 관리자 토큰(Depth 1, "lead-01").
//   - Hop 2: 중간 관리자 토큰(Depth 1) -> 최종 워커 토큰(Depth 2, "worker-01").
//   - 위임 과정에서 스코프와 TTL 은 반드시 단조 감소(축소)해야 하며, 부모 스코프를 초과한 위임 요청은 2차 교환 단계에서 즉시 차단된다 (E2E-32).
//
// 2. 단일 TraceID 연계:
//   - 다단계 위임과 최종 워커 실행 전반에 걸쳐 동일한 TraceID 를 전파하여 단일 분산 감사 추적 체인을 형성한다.
//
// 3. 서브프로세스 격리 vs Inproc 실행 모드 지원:
//   - BinaryPath 가 지정된 경우 독립 서브에이전트 프로세스로 스폰하며,
//     지정되지 않은 경우 프로세스 내부의 PEP 게이트웨이를 통해 워커 단계를 안전하게 집행한다.
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
	"authz-harness/internal/subagent"
)

// MultiHopConfig 는 2-Hop 다단계 프로세스 연쇄 위임 실행에 필요한 설정이다.
type MultiHopConfig struct {
	BinaryPath   string       // authz-harness 실행 바이너리 경로
	WorkspaceDir string       // 격리 작업공간 디렉터리 경로
	StatePath    string       // 상태 파일 경로
	PubJWKSPath  string       // 공개키 JWKS 경로
	ReplayPath   string       // Replay 원장 경로
	AuditPath    string       // 감사 파일 경로
	Audit        audit.Writer // 부모 감사 로거
	Limits       Limits       // 서브프로세스 자원·수명 한계
	Gateway      pep.Gateway  // inproc 모드(BinaryPath 비어 있음)에서 워커 단계를 집행할 PEP 게이트웨이

	// Confiner·Confinement 는 마지막 워커(유일한 서브프로세스)를 OS 격리 아래에서 기동하기 위한 설정이며,
	// SpawnConfig 의 같은 이름 필드로 그대로 전달된다. 영값(nil, Require=false)은 격리 꺼짐이다 (로드맵 11 L-6).
	// 정책 계산은 호출자의 몫이다 (계획 048 D-03). 중간 관리자는 프로세스가 아니라 토큰 교환이므로 격리 대상이 아니다.
	Confiner    confinement.Confiner
	Confinement confinement.Policy
}

// MultiHopDelegationRequest 는 루트 오케스트레이터에서 시작되는 다단계 위임 요청 파라미터다.
type MultiHopDelegationRequest struct {
	TraceID       string        // 단일 분산 추적 식별자
	RootToken     string        // Depth 0 루트 부모 토큰
	LeadSubject   string        // Depth 1 중간 관리자 주체 (예: "lead-01")
	LeadScope     string        // Depth 1 위임 스코프 (예: "file:read file:write")
	WorkerSubject string        // Depth 2 최종 워커 주체 (예: "worker-01")
	WorkerScope   string        // Depth 2 위임 스코프 (예: "file:read" 또는 "file:write")
	TargetFile    string        // 최종 워커가 접근할 파일 상대경로
	Action        domain.Action // 최종 워커 수행 액션 (file:read 또는 file:write)
	Data          []byte        // 쓰기 시 기록 데이터
	// Exchange 는 합성 루트(app.BuildStack)가 조립한 토큰 교환 서비스다.
	// 예산 원장·PIP 스냅샷(lineage_epoch) 같은 옵션이 모두 주입된 정식 조립을 그대로 쓴다.
	Exchange exchange.Service
}

// MultiHopSpawner 는 2-Hop 프로세스 연쇄 스폰 및 위임을 실행하는 오케스트레이터다.
type MultiHopSpawner struct {
	cfg MultiHopConfig
}

// NewMultiHopSpawner 는 새 MultiHopSpawner 인스턴스를 생성한다.
func NewMultiHopSpawner(cfg MultiHopConfig) (*MultiHopSpawner, error) {
	limits, err := cfg.Limits.Normalize()
	if err != nil {
		return nil, err
	}
	cfg.Limits = limits
	return &MultiHopSpawner{cfg: cfg}, nil
}

// MultiHopResult 는 루트 -> 중간 관리자 -> 최종 워커로 이어지는 2-Hop 위임 및 실행의 상세 결과다.
type MultiHopResult struct {
	ExitCode       domain.ExitCode
	TraceID        string
	Hop1Result     *exchange.ExchangeResult
	Hop2Result     *exchange.ExchangeResult
	SpawnResult    *SpawnResult
	InprocResponse *subagent.SubagentResponse
	Error          error
}

// ExecuteMultiHopDetailed 는 루트 -> 중간 관리자 -> 최종 워커로 이어지는 2-Hop 위임 및 실행을 수행하고
// 각 단계의 상세 교환 결과와 최종 워커 실행 결과를 MultiHopResult 에 담아 반환한다.
func (s *MultiHopSpawner) ExecuteMultiHopDetailed(ctx context.Context, req MultiHopDelegationRequest) (*MultiHopResult, error) {
	result := &MultiHopResult{
		TraceID: req.TraceID,
	}

	if req.TraceID == "" {
		result.ExitCode = domain.ExitBadInput
		result.Error = fmt.Errorf("trace_id is required")
		return result, result.Error
	}

	if req.Exchange == nil {
		result.ExitCode = domain.ExitInternalError
		result.Error = fmt.Errorf("multi-hop: exchange service is required")
		return result, result.Error
	}
	exchSvc := req.Exchange

	// 1. Root -> Lead 1차 토큰 교환 (Depth 1)
	leadExchangeRes, err := exchSvc.Exchange(ctx, exchange.ExchangeRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		ParentToken:  req.RootToken,
		ChildSubject: req.LeadSubject,
		Scope:        req.LeadScope,
		Audience:     "authz-harness",
		TTL:          10 * time.Minute,
	}, domain.AuditContext{
		TraceID: req.TraceID,
		Actor:   "root-orchestrator",
		Reason:  "token.exchange.hop1",
	})
	if err != nil {
		// 1차 교환 거부 (사유를 따른 종료 코드: 감사 실패 15, 일반 거부 12)
		result.ExitCode = domain.ExitCodeFromError(err, domain.ExitAuthzDenied)
		result.Error = err
		return result, err
	}
	result.Hop1Result = leadExchangeRes

	// 2. Lead -> Worker 2차 토큰 교환 (Depth 2)
	// (중간 관리자가 하위 워커에게 위임하는 단계)
	workerExchangeRes, err := exchSvc.Exchange(ctx, exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  leadExchangeRes.TokenString,
		ChildSubject: req.WorkerSubject,
		Scope:        req.WorkerScope,
		Audience:     "authz-harness",
		TTL:          5 * time.Minute,
	}, domain.AuditContext{
		TraceID: req.TraceID,
		Actor:   req.LeadSubject,
		Reason:  "token.exchange.hop2",
	})
	if err != nil {
		// 2차 교환 거부 (E2E-32: 중간 관리자의 스코프 초과 위임 차단)
		result.ExitCode = domain.ExitCodeFromError(err, domain.ExitAuthzDenied)
		result.Error = err
		return result, err
	}
	result.Hop2Result = workerExchangeRes

	// 3. Leaf Worker 서브프로세스 스폰 (Depth 2 토큰 주입)
	if s.cfg.BinaryPath != "" {
		spawner, err := NewSubprocessSpawner(SpawnConfig{
			BinaryPath: s.cfg.BinaryPath,
			Args:       WorkerArgs(s.cfg.WorkspaceDir, s.cfg.StatePath, s.cfg.PubJWKSPath, s.cfg.ReplayPath, s.cfg.AuditPath, "", false),
			Audit:      s.cfg.Audit,
			Limits:     s.cfg.Limits,

			Confiner:    s.cfg.Confiner,
			Confinement: s.cfg.Confinement,
		})
		if err != nil {
			result.ExitCode = domain.ExitInternalError
			result.Error = fmt.Errorf("failed to create worker spawner: %w", err)
			return result, result.Error
		}

		res, err := spawner.Spawn(ctx, subagent.SubagentRequest{
			TraceID:  req.TraceID,
			Token:    workerExchangeRes.TokenString,
			Action:   string(req.Action),
			FilePath: req.TargetFile,
			Data:     string(req.Data),
		})
		result.SpawnResult = res
		if err != nil {
			result.ExitCode = domain.ExitInternalError
			result.Error = err
			return result, err
		}
		result.ExitCode = domain.ExitCode(res.ExitCode)
		return result, nil
	}

	// 4. inproc 모드: 서브프로세스 대신 프로세스 내 PEP 게이트웨이로 워커 단계를 집행한다.
	// 게이트웨이도 없으면 인가 판정 없이 성공을 반환하지 않고 Fail-Closed 로 거부한다.
	if s.cfg.Gateway == nil {
		result.ExitCode = domain.ExitInternalError
		result.Error = fmt.Errorf("multi-hop: neither binary path nor pep gateway configured")
		return result, result.Error
	}
	worker, err := subagent.NewWorker(s.cfg.Gateway)
	if err != nil {
		result.ExitCode = domain.ExitInternalError
		result.Error = fmt.Errorf("failed to create inproc worker: %w", err)
		return result, result.Error
	}
	resp, exitCode := worker.Execute(ctx, subagent.SubagentRequest{
		TraceID:  req.TraceID,
		Token:    workerExchangeRes.TokenString,
		Action:   string(req.Action),
		FilePath: req.TargetFile,
		Data:     string(req.Data),
	})
	result.InprocResponse = &resp
	result.ExitCode = domain.ExitCode(exitCode)
	return result, nil
}

// ExecuteMultiHop 은 루트 -> 중간 관리자 -> 최종 워커로 이어지는 2-Hop 위임 및 실행을 수행한다.
func (s *MultiHopSpawner) ExecuteMultiHop(ctx context.Context, req MultiHopDelegationRequest) (domain.ExitCode, error) {
	res, err := s.ExecuteMultiHopDetailed(ctx, req)
	if res != nil {
		return res.ExitCode, err
	}
	return domain.ExitInternalError, err
}
