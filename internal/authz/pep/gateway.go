package pep

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/domain"
	"authz-harness/internal/jail"
)

// Stage 는 5단계 관문 집행 파이프라인의 현재 단계를 식별한다.
type Stage string

const (
	// StageGate0Input 은 기본 입력 인자 유효성 검증 단계다.
	StageGate0Input Stage = "gate0_input"

	// StageGate1AuthN 은 RFC 8725 BCP 및 디지털 서명 토큰 검증 단계다.
	StageGate1AuthN Stage = "gate1_authn"

	// StageGate2AuthZ 는 순수 PDP 인가 결정 단계다.
	StageGate2AuthZ Stage = "gate2_authz"

	// StageGate2cJail 은 Workspace Jail 경로 정규화 및 격리 경계 검증 단계다.
	StageGate2cJail Stage = "gate2c_jail"

	// Stage4Audit 은 Fail-Closed 사전 커밋 감사 로그 기록 단계다.
	Stage4Audit Stage = "stage4_audit"

	// Stage5FileIO 는 격리 파일 I/O 실행 단계다.
	Stage5FileIO Stage = "stage5_io"
)

// NormalizeAction 은 사용자 입력 문자열이나 domain.Action("read"/"file:read")을 표준화한다.
func NormalizeAction(act string) (domain.Action, error) {
	switch strings.ToLower(strings.TrimSpace(act)) {
	case "read", "file:read":
		return domain.ActionFileRead, nil
	case "write", "file:write":
		return domain.ActionFileWrite, nil
	default:
		return "", fmt.Errorf("invalid action: %s (must be read or write)", act)
	}
}

// Request 는 PEP에 파일 작업 집행을 요청하는 매개변수 명세다.
type Request struct {
	Token              string        // Bearer Access Token (RFC 9068)
	Action             domain.Action // domain.ActionFileRead ("file:read") 또는 domain.ActionFileWrite ("file:write")
	Resource           string        // 접근 대상 파일 경로 (상대 경로 권장)
	Data               []byte        // 쓰기 요청 시 기록할 바이트 데이터
	InjectAuditFailure bool          // 결함 주입 스위치: Pre-Commit 감사 실패 시뮬레이션
	ExpectedAudience   string        // 토큰 수신자 기대값 (기본값: "authz-harness")
	ExpectedSubject    string        // 선택적 주체 기대값 검증
	ClockOffset        time.Duration // 선택적 가상 시계 오프셋 (테스트 및 시간 시뮬레이션)
	TraceID            string        // 트랜잭션 추적 식별자 (미지정 시 자동 생성)
}

// Result 는 PEP 관문 집행 결과 및 단계별 판정 세부 정보다.
type Result struct {
	Allowed    bool            `json:"allowed"`
	ExitCode   domain.ExitCode `json:"exit_code"`
	Stage      Stage           `json:"failed_stage,omitempty"`
	Reason     domain.Reason   `json:"reason"`
	Details    string          `json:"details,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	TokenJTI   string          `json:"token_jti,omitempty"`
	SafePath   string          `json:"safe_path,omitempty"`
	BytesRead  int             `json:"bytes_read,omitempty"`
	BytesWrote int             `json:"bytes_wrote,omitempty"`
	Data       []byte          `json:"-"` // 읽기 요청 성공 시 반환되는 파일 내용 (JSON 직렬화 제외)
}

// Gateway 는 파일 I/O 요청에 대한 인가 집행 관문 인터페이스다.
type Gateway interface {
	// Execute 는 5단계 관문(AuthN -> PDP -> Jail -> Audit -> I/O)을 거쳐 파일 작업을 집행한다.
	Execute(ctx context.Context, req Request) (*Result, error)
}

// Config 는 Gateway 생성에 필요한 하위 컴포넌트 의존성 주입 구조체다.
type Config struct {
	Verifier    token.TokenVerifier // Layer 2A: Gate 1 Bearer 토큰 검증기
	PDP         pdp.Service         // Layer 2B: Gate 2 순수 인가 결정 엔진
	Jail        jail.Jail           // Layer 2C: Gate 2c 격리 파일 경계
	AuditWriter audit.Writer        // Layer 1: 감사 로그 기록기
	Clock       domain.Clock        // 결정론적 가상 시계 주입
}

type gateway struct {
	cfg   Config
	clock domain.Clock
}

// NewGateway 는 검증기, PDP, Jail, 감사 기록기를 주입받아 Gateway 인스턴스를 생성한다.
func NewGateway(cfg Config) (Gateway, error) {
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("pep: verifier is required")
	}
	if cfg.PDP == nil {
		return nil, fmt.Errorf("pep: pdp service is required")
	}
	if cfg.Jail == nil {
		return nil, fmt.Errorf("pep: jail is required")
	}
	// AuditWriter 가 nil 이면 거부 (Fail-Closed 감사 보장)
	if cfg.AuditWriter == nil {
		return nil, fmt.Errorf("pep: audit writer is required")
	}

	clk := cfg.Clock
	if clk == nil {
		clk = domain.RealClock{}
	}

	return &gateway{cfg: cfg, clock: clk}, nil
}

// Execute 는 5단계 관문 집행 파이프라인을 실행한다.
func (g *gateway) Execute(ctx context.Context, req Request) (*Result, error) {
	traceID := req.TraceID
	if strings.TrimSpace(traceID) == "" {
		traceID = fmt.Sprintf("pep-%d", g.clock.Now().UnixNano())
	}

	// 0. 기본 입력 인자 유효성 검증
	normAction, actErr := NormalizeAction(string(req.Action))
	cleanResource := strings.TrimSpace(req.Resource)
	if actErr != nil || cleanResource == "" {
		g.logEvent(traceID, "", "", cleanResource, string(req.Action), StageGate0Input, false, domain.ReasonInvalidArguments, "invalid action or resource argument")
		return &Result{
			Allowed:  false,
			ExitCode: domain.ExitBadInput,
			Stage:    StageGate0Input,
			Reason:   domain.ReasonInvalidArguments,
			Details:  "action must be read or write, and resource cannot be empty",
		}, nil
	}
	cleanAction := normAction

	// Stage 1: Gate 1 - AuthN Token Verification
	expectedAud := req.ExpectedAudience
	if expectedAud == "" {
		expectedAud = domain.DefaultAudience
	}

	auditCtx := domain.AuditContext{
		TraceID: traceID,
		Actor:   "pep-gateway",
	}

	claims, err := g.cfg.Verifier.VerifyToken(req.Token, token.VerifyOptions{
		ExpectedAudience: expectedAud,
		ExpectedSubject:  req.ExpectedSubject,
		RecordReplay:     true,
		ClockOffset:      req.ClockOffset,
	}, auditCtx)
	if err != nil {
		reason := extractReasonFromTokenError(err)
		g.logEvent(traceID, "", "", cleanResource, string(cleanAction), StageGate1AuthN, false, reason, err.Error())
		return &Result{
			Allowed:  false,
			ExitCode: domain.ExitTokenInvalid,
			Stage:    StageGate1AuthN,
			Reason:   reason,
			Details:  fmt.Sprintf("Gate 1 authentication failed: %v", err),
		}, nil
	}

	subject := claims.Claims.Subject
	tokenJTI := claims.Claims.JWTID

	// Stage 2: Gate 2 - Pure PDP Authorization
	pdpReq := pdp.Request{
		Subject:      subject,
		Action:       cleanAction,
		Resource:     cleanResource,
		Epoch:        domain.Epoch(claims.Claims.Epoch),
		TokenScope:   claims.Claims.Scope,
		RequireScope: true, // 토큰 기반 PEP 실행은 항상 Scope 검증 필수
		Actor:        claims.Claims.Actor,
		TraceID:      traceID,
	}

	decision, err := g.cfg.PDP.Decide(ctx, pdpReq)
	if err != nil || decision == nil || decision.Decision != pdp.DecisionAllow {
		var reason domain.Reason = domain.ReasonNoActiveGrant
		var details string = "access denied by pdp"
		if decision != nil {
			reason = decision.Reason
			details = decision.Details
		} else if err != nil {
			details = err.Error()
		}

		g.logEvent(traceID, subject, tokenJTI, cleanResource, string(cleanAction), StageGate2AuthZ, false, reason, details)
		return &Result{
			Allowed:  false,
			ExitCode: domain.ExitAuthzDenied,
			Stage:    StageGate2AuthZ,
			Reason:   reason,
			Details:  details,
			Subject:  subject,
			TokenJTI: tokenJTI,
		}, nil
	}

	// Stage 3: Gate 2c - Workspace Jail Boundary Verification
	forWrite := (cleanAction == domain.ActionFileWrite)
	safePath, err := g.cfg.Jail.ResolvePath(cleanResource, forWrite)
	if err != nil {
		jailReason := jail.ReasonFromError(err)
		g.logEvent(traceID, subject, tokenJTI, cleanResource, string(cleanAction), StageGate2cJail, false, jailReason, err.Error())
		return &Result{
			Allowed:  false,
			ExitCode: domain.ExitPathViolation,
			Stage:    StageGate2cJail,
			Reason:   jailReason,
			Details:  fmt.Sprintf("Gate 2c jail path containment violated: %v", err),
			Subject:  subject,
			TokenJTI: tokenJTI,
		}, nil
	}

	// Stage 4: Pre-Commit Audit Verification (Fail-Closed, Zero Side-Effects on Failure)
	if req.InjectAuditFailure {
		// 결함 주입 스위치 활성화 시 감사 로그 기록 실패 강제 시뮬레이션
		return &Result{
			Allowed:  false,
			ExitCode: domain.ExitAuditFailure,
			Stage:    Stage4Audit,
			Reason:   domain.ReasonAuditLogFailed,
			Details:  "injected audit failure simulation (fail-closed)",
			Subject:  subject,
			TokenJTI: tokenJTI,
			SafePath: safePath,
		}, nil
	}

	auditErr := g.logEvent(traceID, subject, tokenJTI, cleanResource, string(cleanAction), Stage4Audit, true, domain.ReasonAuthorized, "pre-commit audit check passed")
	if auditErr != nil {
		// 감사 기록 실패 시 파일 쓰기를 즉시 중단하고 디스크 부작용 0바이트 유지
		return &Result{
			Allowed:  false,
			ExitCode: domain.ExitAuditFailure,
			Stage:    Stage4Audit,
			Reason:   domain.ReasonAuditLogFailed,
			Details:  fmt.Sprintf("audit writer failure (fail-closed): %v", auditErr),
			Subject:  subject,
			TokenJTI: tokenJTI,
			SafePath: safePath,
		}, nil
	}

	// Stage 5: Confined File I/O Execution
	res := &Result{
		Allowed:  true,
		ExitCode: domain.ExitSuccess,
		Stage:    Stage5FileIO,
		Reason:   domain.ReasonAuthorized,
		Details:  "operation successfully authorized and executed",
		Subject:  subject,
		TokenJTI: tokenJTI,
		SafePath: safePath,
	}

	switch cleanAction {
	case domain.ActionFileRead:
		data, err := g.cfg.Jail.ReadFile(cleanResource)
		if err != nil {
			return nil, fmt.Errorf("pep: failed to read file in jail: %w", err)
		}
		res.Data = data
		res.BytesRead = len(data)

	case domain.ActionFileWrite:
		if err := g.cfg.Jail.WriteFile(cleanResource, req.Data); err != nil {
			return nil, fmt.Errorf("pep: failed to write file in jail: %w", err)
		}
		res.BytesWrote = len(req.Data)
	}

	// 최종 완료 감사 이벤트 기록
	_ = g.logEvent(traceID, subject, tokenJTI, cleanResource, string(cleanAction), Stage5FileIO, true, domain.ReasonAuthorized, "file I/O execution completed")

	return res, nil
}

// logEvent 는 Zero Leakage 원칙에 따라 서명된 Bearer 원본 토큰은 일체 기록하지 않고,
// 오직 TokenJTI, Subject, 경로, 액션, 성공 여부만 감사 로그에 기록한다.
func (g *gateway) logEvent(traceID, subject, jti, resource, action string, stage Stage, success bool, reason domain.Reason, details string) error {
	if g.cfg.AuditWriter == nil {
		return fmt.Errorf("pep: nil audit writer")
	}

	actionName := "pep.allow"
	if !success {
		actionName = "pep.deny"
	}
	stepName := string(stage)
	if action != "" {
		stepName = "pep." + action
	}

	event := audit.Event{
		Timestamp: g.clock.Now().UTC(),
		TraceID:   traceID,
		Step:      stepName,
		Actor:     subject,
		Action:    actionName,
		Resource:  resource,
		Decision:  map[bool]string{true: "allow", false: "deny"}[success],
		Reason:    string(reason),
		TokenJTI:  jti,
		Success:   success,
		Metadata: map[string]interface{}{
			"stage":            string(stage),
			"requested_action": action,
			"details":          details,
		},
	}
	if subject == "" {
		event.Actor = "anonymous"
	}

	return g.cfg.AuditWriter.Log(event)
}

func extractReasonFromTokenError(err error) domain.Reason {
	if err == nil {
		return domain.ReasonAuthorized
	}
	return domain.ReasonFromError(err, domain.ReasonInvalidToken)
}
