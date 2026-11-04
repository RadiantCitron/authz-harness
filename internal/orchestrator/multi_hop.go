package orchestrator

import (
	"context"
	"fmt"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
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
	TokenIssuer   token.TokenIssuer
	TokenVerifier token.TokenVerifier
	ClientReg     token.ClientRegistry
	Clock         domain.Clock
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

// ExecuteMultiHop 은 루트 -> 중간 관리자 -> 최종 워커로 이어지는 2-Hop 위임 및 실행을 수행한다.
func (s *MultiHopSpawner) ExecuteMultiHop(ctx context.Context, req MultiHopDelegationRequest) (domain.ExitCode, error) {
	if req.TraceID == "" {
		return domain.ExitBadInput, fmt.Errorf("trace_id is required")
	}

	// 1. Root -> Lead 1차 토큰 교환 (Depth 1)
	downscopeValidator := exchange.NewDownscopeValidator()
	exchSvc := exchange.NewExchangeService(
		req.TokenIssuer,
		req.TokenVerifier,
		req.ClientReg,
		downscopeValidator,
		s.cfg.Audit,
		req.Clock,
	)

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
		// 1차 교환 거부
		return domain.ExitAuthzDenied, err
	}

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
		return domain.ExitAuthzDenied, err
	}

	// 3. Leaf Worker 서브프로세스 스폰 (Depth 2 토큰 주입)
	if s.cfg.BinaryPath != "" {
		spawner, err := NewSubprocessSpawner(SpawnConfig{
			BinaryPath: s.cfg.BinaryPath,
			Args: []string{
				"subagent", "worker",
				"-workspace", s.cfg.WorkspaceDir,
				"-state-file", s.cfg.StatePath,
				"-pub-jwks-file", s.cfg.PubJWKSPath,
				"-replay-file", s.cfg.ReplayPath,
				"-audit-file", s.cfg.AuditPath,
			},
			Audit:  s.cfg.Audit,
			Limits: s.cfg.Limits,
		})
		if err != nil {
			return domain.ExitInternalError, fmt.Errorf("failed to create worker spawner: %w", err)
		}

		res, err := spawner.Spawn(ctx, subagent.SubagentRequest{
			TraceID:  req.TraceID,
			Token:    workerExchangeRes.TokenString,
			Action:   string(req.Action),
			FilePath: req.TargetFile,
			Data:     string(req.Data),
		})
		if err != nil {
			return domain.ExitInternalError, err
		}
		return domain.ExitCode(res.ExitCode), nil
	}

	return domain.ExitSuccess, nil
}
