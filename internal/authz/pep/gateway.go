package pep

import (
	"context"
	"fmt"
	"log/slog"
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
	Token                string        // Bearer Access Token (RFC 9068)
	Action               domain.Action // domain.ActionFileRead ("file:read") 또는 domain.ActionFileWrite ("file:write")
	Resource             string        // 접근 대상 파일 경로 (상대 경로 권장)
	Data                 []byte        // 쓰기 요청 시 기록할 바이트 데이터
	InjectAuditFailure   bool          // 결함 주입 스위치: Pre-Commit 감사 실패 시뮬레이션
	InjectRevokeBeforeIO bool          // 결함 주입 스위치: I/O 직전 Grant 전면 회수 시뮬레이션 (TOCTOU 테스트용)
	ExpectedAudience     string        // 토큰 수신자 기대값 (기본값: "authz-harness")
	ExpectedSubject      string        // 선택적 주체 기대값 검증
	ClockOffset          time.Duration // 선택적 가상 시계 오프셋 (테스트 및 시간 시뮬레이션)
	TraceID              string        // 트랜잭션 추적 식별자 (미지정 시 자동 생성)
	RequireTraceID       bool          // true 인 경우 TraceID 누락 시 Gate 0 에서 즉각 차단 (E2E-28 검증용)
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
	Logger      *slog.Logger        // 관측성 운영 로거 주입 (미주입 시 slog.Default())
}

type gateway struct {
	cfg    Config
	clock  domain.Clock
	logger *slog.Logger
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

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &gateway{cfg: cfg, clock: clk, logger: logger}, nil
}

// pipelineState 는 파이프라인 진행 과정에서 점진적으로 채워지는 불변 실행 상태다.
type pipelineState struct {
	traceID     string
	resource    string
	normAction  domain.Action
	subject     string
	tokenJTI    string
	callerID    string
	safePath    string
	failedStage Stage
}

// Execute 는 5단계 관문 집행 파이프라인을 실행하며 단일 출구(finalize)를 보장한다.
func (g *gateway) Execute(ctx context.Context, req Request) (*Result, error) {
	traceID := req.TraceID
	if strings.TrimSpace(traceID) == "" {
		traceID = fmt.Sprintf("pep-%d", g.clock.Now().UnixNano())
	}

	state := &pipelineState{
		traceID:  traceID,
		resource: strings.TrimSpace(req.Resource),
	}

	res, err := g.runPipeline(ctx, req, state)
	return g.finalize(ctx, state, res, err)
}

// runStage 는 파이프라인 단계별 Before/After Around 계측 래퍼다.
func (g *gateway) runStage(ctx context.Context, state *pipelineState, stage Stage, fn func() error) error {
	start := g.clock.Now()
	g.logger.DebugContext(ctx, "pep stage entering",
		"trace_id", state.traceID,
		"stage", string(stage),
		"resource", state.resource,
		"subject", state.subject,
	)

	err := fn()
	durationMs := g.clock.Now().Sub(start).Milliseconds()

	if err != nil {
		state.failedStage = stage
		reason := domain.ReasonFromError(err, domain.ReasonInternalError)
		g.logger.WarnContext(ctx, "pep stage blocked",
			"trace_id", state.traceID,
			"stage", string(stage),
			"reason", string(reason),
			"duration_ms", durationMs,
			"resource", state.resource,
			"subject", state.subject,
		)
		return err
	}

	g.logger.InfoContext(ctx, "pep stage passed",
		"trace_id", state.traceID,
		"stage", string(stage),
		"duration_ms", durationMs,
		"resource", state.resource,
		"subject", state.subject,
	)
	return nil
}

// runPipeline 은 Gate 0부터 Stage 5까지 순차적으로 실행하며, 차단 시 표준 *domain.Error 를 반환한다.
func (g *gateway) runPipeline(ctx context.Context, req Request, state *pipelineState) (*Result, error) {
	// 0. 기본 입력 인자 유효성 검증
	if err := g.runStage(ctx, state, StageGate0Input, func() error {
		if req.RequireTraceID && strings.TrimSpace(req.TraceID) == "" {
			return domain.NewError(domain.ReasonMissingTraceContext, string(StageGate0Input), "trace_id is required but missing", nil)
		}
		normAction, actErr := NormalizeAction(string(req.Action))
		if actErr != nil || state.resource == "" {
			return domain.NewError(domain.ReasonInvalidArguments, string(StageGate0Input), "action must be read or write, and resource cannot be empty", actErr)
		}
		state.normAction = normAction
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 1: Gate 1 - AuthN Token Verification
	var verifiedClaims *domain.VerifiedClaims
	if err := g.runStage(ctx, state, StageGate1AuthN, func() error {
		expectedAud := req.ExpectedAudience
		if expectedAud == "" {
			expectedAud = domain.DefaultAudience
		}

		auditCtx := domain.AuditContext{
			TraceID: state.traceID,
			Actor:   "pep-gateway",
		}

		c, verifyErr := g.cfg.Verifier.VerifyToken(req.Token, token.VerifyOptions{
			ExpectedAudience: expectedAud,
			ExpectedSubject:  req.ExpectedSubject,
			RecordReplay:     true,
			ClockOffset:      req.ClockOffset,
		}, auditCtx)
		if verifyErr != nil {
			reason := extractReasonFromTokenError(verifyErr)
			return domain.NewError(reason, string(StageGate1AuthN), fmt.Sprintf("Gate 1 authentication failed: %v", verifyErr), verifyErr)
		}

		verifiedClaims = c
		state.subject = verifiedClaims.Claims.Subject
		state.tokenJTI = verifiedClaims.Claims.JWTID
		if verifiedClaims.Claims.Actor != nil && verifiedClaims.Claims.Actor.Subject != "" {
			state.callerID = verifiedClaims.Claims.Actor.Subject
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 2: Gate 2 - Pure PDP Authorization
	if err := g.runStage(ctx, state, StageGate2AuthZ, func() error {
		pdpReq := pdp.Request{
			Subject:      state.subject,
			Action:       state.normAction,
			Resource:     state.resource,
			Epoch:        domain.Epoch(verifiedClaims.Claims.Epoch),
			TokenScope:   verifiedClaims.Claims.Scope,
			RequireScope: true, // 토큰 기반 PEP 실행은 항상 Scope 검증 필수
			Actor:        verifiedClaims.Claims.Actor,
			TraceID:      state.traceID,
		}

		decision, decideErr := g.cfg.PDP.Decide(ctx, pdpReq)
		if decideErr != nil {
			return domain.NewError(domain.ReasonFromError(decideErr, domain.ReasonInternalError), string(StageGate2AuthZ), fmt.Sprintf("pdp evaluation error: %v", decideErr), decideErr)
		}
		if decision == nil || decision.Decision != pdp.DecisionAllow {
			reason := domain.ReasonNoActiveGrant
			details := "access denied by pdp"
			if decision != nil {
				reason = decision.Reason
				details = decision.Details
			}
			return domain.NewError(reason, string(StageGate2AuthZ), details, nil)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 3: Gate 2c - Workspace Jail Boundary Verification
	if err := g.runStage(ctx, state, StageGate2cJail, func() error {
		forWrite := (state.normAction == domain.ActionFileWrite)
		safePath, jailErr := g.cfg.Jail.ResolvePath(state.resource, forWrite)
		if jailErr != nil {
			jailReason := jail.ReasonFromError(jailErr)
			return domain.NewError(jailReason, string(StageGate2cJail), fmt.Sprintf("Gate 2c jail path containment violated: %v", jailErr), jailErr)
		}
		state.safePath = safePath
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 4: Pre-Commit Audit Verification (Fail-Closed, Zero Side-Effects on Failure)
	if err := g.runStage(ctx, state, Stage4Audit, func() error {
		if req.InjectAuditFailure {
			return domain.NewError(domain.ReasonAuditLogFailed, string(Stage4Audit), "injected audit failure simulation (fail-closed)", nil)
		}
		auditErr := g.logEvent(state, Stage4Audit, true, domain.ReasonAuthorized, "pre-commit audit check passed")
		if auditErr != nil {
			return domain.NewError(domain.ReasonAuditLogFailed, string(Stage4Audit), fmt.Sprintf("audit writer failure (fail-closed): %v", auditErr), auditErr)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 5: Confined File I/O Execution
	var finalRes *Result
	if err := g.runStage(ctx, state, Stage5FileIO, func() error {
		res := &Result{
			Allowed:  true,
			ExitCode: domain.ExitSuccess,
			Stage:    Stage5FileIO,
			Reason:   domain.ReasonAuthorized,
			Details:  "operation successfully authorized and executed",
			Subject:  state.subject,
			TokenJTI: state.tokenJTI,
			SafePath: state.safePath,
		}

		switch state.normAction {
		case domain.ActionFileRead:
			data, readErr := g.cfg.Jail.ReadFile(state.resource)
			if readErr != nil {
				return domain.NewError(domain.ReasonInternalError, string(Stage5FileIO), fmt.Sprintf("pep: failed to read file in jail: %v", readErr), readErr)
			}
			res.Data = data
			res.BytesRead = len(data)

		case domain.ActionFileWrite:
			if writeErr := g.cfg.Jail.WriteFile(state.resource, req.Data); writeErr != nil {
				return domain.NewError(domain.ReasonInternalError, string(Stage5FileIO), fmt.Sprintf("pep: failed to write file in jail: %v", writeErr), writeErr)
			}
			res.BytesWrote = len(req.Data)
		}

		finalRes = res
		return nil
	}); err != nil {
		return nil, err
	}

	return finalRes, nil
}

// finalize 는 SESE 단일 출구 지점으로, 성공 및 모든 실패 경로를 정규화하고
// 차단 감사 기록 및 최종 완료 감사/로그를 단 1곳에서 결정론적으로 마감한다.
func (g *gateway) finalize(ctx context.Context, state *pipelineState, res *Result, runErr error) (*Result, error) {
	if runErr != nil {
		reason := domain.ReasonFromError(runErr, domain.ReasonInternalError)
		exitCode := domain.ExitCodeFromError(runErr, domain.ExitCodeForReason(reason))
		failedStage := state.failedStage

		// 단일 출구 차단 감사 기록 (Stage4 감사 실패 시 중복 기록 시도 방지)
		if failedStage != Stage4Audit {
			if auditErr := g.logEvent(state, failedStage, false, reason, runErr.Error()); auditErr != nil {
				g.logger.ErrorContext(ctx, "failed to record block audit event",
					"trace_id", state.traceID,
					"error", auditErr.Error(),
				)
			}
		}

		g.logger.WarnContext(ctx, "pep execution denied or failed",
			"trace_id", state.traceID,
			"stage", string(failedStage),
			"reason", string(reason),
			"exit_code", int(exitCode),
			"subject", state.subject,
			"agent_id", state.subject,
			"caller_id", state.callerID,
		)

		return &Result{
			Allowed:  false,
			ExitCode: exitCode,
			Stage:    failedStage,
			Reason:   reason,
			Details:  runErr.Error(),
			Subject:  state.subject,
			TokenJTI: state.tokenJTI,
			SafePath: state.safePath,
		}, nil
	}

	// 정상 실행 완료 감사 기록
	if auditErr := g.logEvent(state, Stage5FileIO, true, domain.ReasonAuthorized, "file I/O execution completed"); auditErr != nil {
		g.logger.ErrorContext(ctx, "failed to record completion audit event",
			"trace_id", state.traceID,
			"error", auditErr.Error(),
		)
	}

	g.logger.InfoContext(ctx, "pep execution succeeded",
		"trace_id", state.traceID,
		"resource", state.resource,
		"subject", state.subject,
		"agent_id", state.subject,
		"caller_id", state.callerID,
		"bytes_read", res.BytesRead,
		"bytes_wrote", res.BytesWrote,
	)

	return res, nil
}

// logEvent 는 Zero Leakage 원칙에 따라 서명된 Bearer 원본 토큰은 일체 기록하지 않고,
// TokenJTI, Subject(AgentID), CallerID(위임 계보), 경로, 액션, 성공 여부만 감사 로그에 기록한다.
func (g *gateway) logEvent(state *pipelineState, stage Stage, success bool, reason domain.Reason, details string) error {
	if g.cfg.AuditWriter == nil {
		return fmt.Errorf("pep: nil audit writer")
	}

	actionName := "pep.allow"
	if !success {
		actionName = "pep.deny"
	}
	stepName := string(stage)
	if state.normAction != "" {
		stepName = "pep." + string(state.normAction)
	}

	event := audit.Event{
		Timestamp: g.clock.Now().UTC(),
		TraceID:   state.traceID,
		Step:      stepName,
		Actor:     state.subject,
		AgentID:   state.subject,
		Action:    actionName,
		Resource:  state.resource,
		Decision:  map[bool]string{true: "allow", false: "deny"}[success],
		Reason:    string(reason),
		TokenJTI:  state.tokenJTI,
		Success:   success,
		Metadata: map[string]interface{}{
			"stage":            string(stage),
			"requested_action": string(state.normAction),
			"details":          details,
		},
	}
	if event.Actor == "" {
		event.Actor = "anonymous"
	}
	if state.callerID != "" {
		event.Metadata["caller_id"] = state.callerID
	}

	return g.cfg.AuditWriter.Log(event)
}

func extractReasonFromTokenError(err error) domain.Reason {
	if err == nil {
		return domain.ReasonAuthorized
	}
	return domain.ReasonFromError(err, domain.ReasonInvalidToken)
}

