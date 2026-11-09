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
	"authz-harness/internal/execguard"
	"authz-harness/internal/jail"
	"authz-harness/internal/netguard"
	"authz-harness/internal/observe"
	"authz-harness/internal/pipeline"
)

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
	// AllowNegativeClockOffset 이 false(기본) 이면 음수 ClockOffset 을 input 단계에서 거부한다(만료 토큰 부활 방지).
	// nbf 이전 시각을 일부러 시뮬레이션하는 하네스 시나리오만 켠다. CLI·서브프로세스 워커는 노출하지 않는다.
	AllowNegativeClockOffset bool
	TraceID                  string // 트랜잭션 추적 식별자 (미지정 시 자동 생성)
	RequireTraceID           bool   // true 인 경우 TraceID 누락 시 input 단계에서 즉각 차단 (E2E-28 검증용)
}

// Result 는 PEP 관문 집행 결과 및 단계별 판정 세부 정보다.
type Result struct {
	Allowed    bool            `json:"allowed"`
	ExitCode   domain.ExitCode `json:"exit_code"`
	Stage      domain.Stage    `json:"failed_stage,omitempty"`
	Reason     domain.Reason   `json:"reason"`
	Details    string          `json:"details,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	TokenJTI   string          `json:"token_jti,omitempty"`
	SafePath   string          `json:"safe_path,omitempty"`
	BytesRead  int             `json:"bytes_read,omitempty"`
	BytesWrote int             `json:"bytes_wrote,omitempty"`
	Data       []byte          `json:"-"` // 읽기 요청 성공 시 반환되는 파일 내용 (JSON 직렬화 제외)
	// Passed 는 이 요청이 실제로 통과한 단계를 통과한 순서대로 담는다. 실패한 단계는 들어 있지 않다.
	// 조건부 단계(승인·예산)가 이 요청에 해당 없으면 빠져 있으므로, 화면은 순서를 추론하지 않고 이 기록을 읽는다.
	Passed []domain.Stage `json:"passed_stages,omitempty"`
}

// Gateway 는 파일 I/O 요청에 대한 인가 집행 관문 인터페이스다.
type Gateway interface {
	// Execute 는 파이프라인 단계(input -> authn -> authz -> boundary -> replay -> approval -> budget -> precommit_audit -> execute -> settle)을 거쳐 파일 작업을 집행한다.
	Execute(ctx context.Context, req Request) (*Result, error)
}

// ApprovalConsumer 는 승인을 ID 로 찾아 재검증한 뒤 소비(삭제)하는 포트다.
type ApprovalConsumer interface {
	ConsumeApproval(id string, b domain.ApprovalBinding, now time.Time) error
}

// Config 는 Gateway 생성에 필요한 하위 컴포넌트 의존성 주입 구조체다.
type Config struct {
	Verifier         token.TokenVerifier // Layer 2A: authn 단계 Bearer 토큰 검증기
	PDP              pdp.Service         // Layer 2B: authz 단계 순수 인가 결정 엔진
	Jail             jail.Jail           // Layer 2C: boundary 단계 격리 파일 경계
	AuditWriter      audit.Writer        // Layer 1: 감사 로그 기록기
	Clock            domain.Clock        // 결정론적 가상 시계 주입
	Observer         observe.Observer    // 관측성 포트 주입 (미주입 시 NoopObserver, 항상 WrapSafe 적용)
	StageObserver    func(domain.Stage)  // 선택: 단계 통과 직후 호출되는 관찰자(단위 시험 전용, BuildStack 은 배선하지 않음)
	ApprovalConsumer ApprovalConsumer    // 선택: 승인 소비기. 승인으로 허용된 요청인데 없으면 Fail-Closed(16)
	BudgetLedger     domain.BudgetLedger // 선택: 예산 토큰(Budget != nil) 집행용 원장. 없으면 예산 토큰은 Fail-Closed 거부
	NetGuard         *netguard.Guard     // 선택: net:fetch 가드. nil 이면 net:fetch 는 boundary 단계에서 Fail-Closed(16)
	ExecRunner       *execguard.Runner   // 선택: exec:run 실행기. nil 이면 exec:run 은 boundary 단계에서 Fail-Closed(16)
}

type gateway struct {
	cfg    Config
	clock  domain.Clock
	obs    observe.Observer
	engine *pipeline.Engine[Call]
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

	g := &gateway{cfg: cfg, clock: clk, obs: observe.WrapSafe(cfg.Observer)}
	eng, err := pipeline.New[Call](g.assemble(), stageHook{g})
	if err != nil {
		return nil, fmt.Errorf("pep: assemble pipeline: %w", err)
	}
	g.engine = eng
	return g, nil
}

// pipelineState 는 파이프라인 진행 과정에서 점진적으로 채워지는 실행 상태다.
// 필드마다 채우는 단계를 주석으로 밝힌다(ADR 0008 3장).
type pipelineState struct {
	traceID    string // Execute
	resource   string // Execute, input(net:fetch 는 정규화)
	argHash    string // Execute, input(net:fetch 는 URL 지문). 요청 데이터 지문이며 원문은 기록하지 않는다
	normAction domain.Action
	tool       Tool // input
	subject    string
	tokenJTI   string
	callerID   string
	safePath   string // boundary
	claims     *domain.VerifiedClaims
	approvalID string    // authz: PDP 가 승인으로 allow 했을 때 소비할 승인 ID
	evalNow    time.Time // authz: PDP 판정과 승인 소비에 쓰는 같은 시각
	stepStart  time.Time // Hook: 현재 단계 시작 시각
	out        Output    // execute

	// 예산 집행 상태. budgeted 는 authn, consumed·refundWriteBytes 는 budget 이 채운다.
	budgeted         bool
	consumed         bool
	refundWriteBytes int64
}

func step(id domain.Stage, kind domain.StageKind, applies func(*Call) bool, run func(context.Context, *Call) error) pipeline.Step[Call] {
	s := pipeline.Step[Call]{ID: string(id), Kind: pipeline.Kind(kind), Run: run}
	if applies != nil {
		s.Applies = func(c *Call) bool { return applies(c) }
	}
	return s
}

// assemble 은 PEP 의 조립 목록이다. 순서와 성격은 domain.PEPStages() 와 같아야 하며 시험이 강제한다.
func (g *gateway) assemble() []pipeline.Step[Call] {
	input := step(domain.StageInput, domain.KindCheck, nil, g.input)
	authn := step(domain.StageAuthn, domain.KindCheck, nil, g.authn)
	authz := step(domain.StageAuthz, domain.KindDecide, nil, g.authz)
	boundary := step(domain.StageBoundary, domain.KindCheck, nil, g.boundary)
	replay := step(domain.StageReplay, domain.KindConsume, nil, g.replay)
	approval := step(domain.StageApproval, domain.KindConsume, approved, g.approval)
	budgetStep := step(domain.StageBudget, domain.KindConsume, budgeted, g.budget)
	budgetStep.Compensate = g.refund
	precommit := step(domain.StagePrecommitAudit, domain.KindRecord, nil, g.precommitAudit)
	execute := step(domain.StageExecute, domain.KindExecute, nil, g.execute)
	settle := step(domain.StageSettle, domain.KindSettle, postCharged, g.settle)
	return []pipeline.Step[Call]{input, authn, authz, boundary, replay, approval, budgetStep, precommit, execute, settle}
}

func approved(c *Call) bool { return c.st.approvalID != "" }
func budgeted(c *Call) bool { return c.st.budgeted }
func postCharged(c *Call) bool {
	return c.st.budgeted && c.st.tool.BudgetPlan(c).PostCharge
}

// Execute 는 파이프라인 엔진을 돌리고 단일 출구(finalize)에서 마감한다.
func (g *gateway) Execute(ctx context.Context, req Request) (*Result, error) {
	traceID := req.TraceID
	if strings.TrimSpace(traceID) == "" {
		traceID = fmt.Sprintf("pep-%d", g.clock.Now().UnixNano())
	}
	c := &Call{cfg: &g.cfg, req: req, st: &pipelineState{
		traceID:  traceID,
		resource: strings.TrimSpace(req.Resource),
		argHash:  domain.DataDigest(req.Data),
	}}
	tr := g.engine.Run(ctx, c)
	return g.finalize(ctx, c.st, tr)
}

// stageHook 은 단계마다 관측을 남기고 StageObserver 를 동기로 부르는 Hook 구현이다.
type stageHook struct{ g *gateway }

func (h stageHook) OnStepStart(ctx context.Context, id string, c *Call) {
	c.st.stepStart = h.g.clock.Now()
	h.g.obs.OnStageStart(ctx, c.st.traceID, id,
		observe.Attr{Key: "resource", Value: c.st.resource},
		observe.Attr{Key: "subject", Value: c.st.subject},
	)
}

func (h stageHook) OnStepEnd(ctx context.Context, id string, c *Call, err error) {
	if err == nil && h.g.cfg.StageObserver != nil {
		h.g.cfg.StageObserver(domain.Stage(id))
	}
	durationMs := h.g.clock.Now().Sub(c.st.stepStart).Milliseconds()
	if err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonInternalError)
		h.g.obs.OnStageEnd(ctx, c.st.traceID, id, false,
			observe.Attr{Key: "reason", Value: string(reason)},
			observe.Attr{Key: "duration_ms", Value: durationMs},
			observe.Attr{Key: "resource", Value: c.st.resource},
			observe.Attr{Key: "subject", Value: c.st.subject},
		)
		return
	}
	h.g.obs.OnStageEnd(ctx, c.st.traceID, id, true,
		observe.Attr{Key: "duration_ms", Value: durationMs},
		observe.Attr{Key: "resource", Value: c.st.resource},
		observe.Attr{Key: "subject", Value: c.st.subject},
	)
}

// input: 기본 입력 인자 유효성 검증과 도구별 입력 정규화
func (g *gateway) input(_ context.Context, c *Call) error {
	st, req := c.st, c.req
	if req.RequireTraceID && strings.TrimSpace(req.TraceID) == "" {
		return domain.NewError(domain.ReasonMissingTraceContext, "trace_id is required but missing", nil)
	}
	// 음수 오프셋은 만료된 토큰을 되살리는 손잡이이므로 명시 허용 없이는 인증 전에 거부한다 (Fail-Closed).
	if req.ClockOffset < 0 && !req.AllowNegativeClockOffset {
		return domain.NewError(domain.ReasonInvalidArguments, "clock offset must not be negative", nil)
	}
	normAction, actErr := domain.ParseAction(string(req.Action))
	var tool Tool
	if actErr == nil {
		var found bool
		tool, found = toolFor(normAction)
		if !found {
			actErr = fmt.Errorf("pep: no tool registered for action %q", normAction)
		}
	}
	if actErr != nil || st.resource == "" {
		return domain.NewError(domain.ReasonInvalidArguments, "action must be file:read, file:write, net:fetch or exec:run, and resource cannot be empty", actErr)
	}
	st.normAction = normAction
	st.tool = tool
	return tool.Prepare(c)
}

// authn: Bearer 토큰 검증
func (g *gateway) authn(_ context.Context, c *Call) error {
	st, req := c.st, c.req
	expectedAud := req.ExpectedAudience
	if expectedAud == "" {
		expectedAud = domain.DefaultAudience
	}
	auditCtx := domain.AuditContext{TraceID: st.traceID, Actor: "pep-gateway"}
	vc, verifyErr := g.cfg.Verifier.VerifyToken(req.Token, token.VerifyOptions{
		ExpectedAudience: expectedAud,
		ExpectedSubject:  req.ExpectedSubject,
		RecordReplay:     false,
		CheckReplay:      true,
		ClockOffset:      req.ClockOffset,

		AllowNegativeClockOffset: req.AllowNegativeClockOffset,
	}, auditCtx)
	if verifyErr != nil {
		reason := extractReasonFromTokenError(verifyErr)
		return domain.NewError(reason, fmt.Sprintf("authn stage authentication failed: %v", verifyErr), verifyErr)
	}
	st.claims = vc
	st.subject = vc.Claims.Subject
	st.tokenJTI = vc.Claims.JWTID
	if vc.Claims.Actor != nil && vc.Claims.Actor.Subject != "" {
		st.callerID = vc.Claims.Actor.Subject
	}
	if vc.Claims.Budget != nil {
		st.budgeted = true
		if g.cfg.BudgetLedger == nil {
			return domain.NewError(domain.ReasonInternalError, "budget token presented but no budget ledger is configured (fail-closed)", nil)
		}
	}
	return nil
}

// authz: 순수 PDP 인가 결정
func (g *gateway) authz(ctx context.Context, c *Call) error {
	st := c.st
	st.evalNow = g.clock.Now().UTC().Add(c.req.ClockOffset)
	decision, decideErr := g.cfg.PDP.Decide(ctx, pdp.Request{
		Subject:      st.subject,
		Action:       st.normAction,
		Resource:     st.resource,
		Epoch:        domain.Epoch(st.claims.Claims.Epoch),
		TokenScope:   st.claims.Claims.Scope,
		RequireScope: true, // 토큰 기반 PEP 실행은 항상 Scope 검증 필수
		Actor:        st.claims.Claims.Actor,
		TraceID:      st.traceID,
		TokenJTI:     st.tokenJTI,
		ArgHash:      st.argHash,
		Now:          st.evalNow,
	})
	if decideErr != nil {
		return domain.NewError(domain.ReasonFromError(decideErr, domain.ReasonInternalError), fmt.Sprintf("pdp evaluation error: %v", decideErr), decideErr)
	}
	if decision == nil || decision.Decision != pdp.DecisionAllow {
		reason := domain.ReasonNoActiveGrant
		details := "access denied by pdp"
		if decision != nil {
			reason = decision.Reason
			details = decision.Details
		}
		return domain.NewError(reason, details, nil)
	}
	st.approvalID = decision.ApprovalID
	return nil
}

// boundary: 도구별 경계 검사 (jail 경로, egress 허용 목록, 실행 허용 목록)
func (g *gateway) boundary(_ context.Context, c *Call) error {
	return c.st.tool.CheckBoundary(c)
}

// replay: 모든 검사를 통과한 뒤 jti 를 소비한다. deny·ask·경계 거부에서는 소비하지 않아 같은 토큰으로 재시도할 수 있다.
func (g *gateway) replay(_ context.Context, c *Call) error {
	return g.cfg.Verifier.ConsumeReplay(c.st.claims.Claims, domain.AuditContext{TraceID: c.st.traceID, Actor: "pep-gateway"})
}

// approval: 승인 소비. 소비한 승인은 이후 단계가 실패해도 되돌리지 않는다.
func (g *gateway) approval(_ context.Context, c *Call) error {
	st := c.st
	if g.cfg.ApprovalConsumer == nil {
		return domain.NewError(domain.ReasonInternalError, "approval required but no approval consumer is configured (fail-closed)", nil)
	}
	binding := domain.ApprovalBinding{Subject: st.subject, Action: st.normAction, Resource: st.resource, TokenJTI: st.tokenJTI, ArgHash: st.argHash}
	if consumeErr := g.cfg.ApprovalConsumer.ConsumeApproval(st.approvalID, binding, st.evalNow); consumeErr != nil {
		return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), fmt.Sprintf("approval consume denied: %v", consumeErr), consumeErr)
	}
	// 잠금은 이미 풀렸다. 감사 실패는 Fail-Closed(승인은 이미 소멸).
	if auditErr := g.logApprovalConsumed(st); auditErr != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("approval audit failure (fail-closed): %v", auditErr), auditErr)
	}
	return nil
}

// budget: 예산 토큰의 호출 1회와 쓰기 바이트를 실행 전에 차감한다. 이후 단계가 실패하면 refund 가 보상한다.
func (g *gateway) budget(ctx context.Context, c *Call) error {
	st := c.st
	var n int64
	if c.st.tool.BudgetPlan(c).ChargeWriteBytes {
		n = int64(len(c.req.Data))
	}
	if consumeErr := g.cfg.BudgetLedger.Consume(st.tokenJTI, 1, 0, n); consumeErr != nil {
		return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), fmt.Sprintf("budget consume denied: %v", consumeErr), consumeErr)
	}
	st.consumed = true
	st.refundWriteBytes = n
	// 차감 사실을 감사에 남긴다. 실패한 단계 자신의 보상은 엔진이 부르지 않으므로 여기서 직접 환급한다.
	if auditErr := g.logBudgetConsumed(st); auditErr != nil {
		g.refund(ctx, c)
		st.consumed = false
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("budget audit failure (fail-closed): %v", auditErr), auditErr)
	}
	return nil
}

// refund 는 budget 의 보상이다. 환급 실패는 원래 거부 사유를 바꾸지 않고 운영 로그에만 남긴다.
func (g *gateway) refund(ctx context.Context, c *Call) {
	st := c.st
	if !st.consumed {
		return
	}
	if err := g.cfg.BudgetLedger.Refund(st.tokenJTI, 1, 0, st.refundWriteBytes); err != nil {
		g.obs.OnError(ctx, st.traceID, "failed to refund budget",
			observe.Attr{Key: "token_jti", Value: st.tokenJTI},
			observe.Attr{Key: "error", Value: err.Error()},
		)
	}
}

// precommit_audit: 실행 전 감사 증거 기록 (Fail-Closed, 실패 시 부작용 없음)
func (g *gateway) precommitAudit(_ context.Context, c *Call) error {
	if c.req.InjectAuditFailure {
		return domain.NewError(domain.ReasonAuditLogFailed, "injected audit failure simulation (fail-closed)", nil)
	}
	if auditErr := g.logEvent(c.st, domain.StagePrecommitAudit, true, domain.ReasonAuthorized, "pre-commit audit check passed", ""); auditErr != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("audit writer failure (fail-closed): %v", auditErr), auditErr)
	}
	return nil
}

// execute: 도구 실행
func (g *gateway) execute(ctx context.Context, c *Call) error {
	if !c.st.tool.BudgetPlan(c).RefundAfterStart {
		// 실행이 시작되면 실패해도 환급하지 않는다(부작용이 이미 났을 수 있다).
		c.st.consumed = false
	}
	out, err := c.st.tool.Execute(ctx, c)
	if err != nil {
		return err
	}
	c.st.out = out
	return nil
}

// settle: 실행 뒤에야 아는 출력 바이트를 정산한다. 실패하면 결과를 돌려주지 않는다.
func (g *gateway) settle(_ context.Context, c *Call) error {
	st := c.st
	if consumeErr := g.cfg.BudgetLedger.Consume(st.tokenJTI, 0, int64(len(st.out.Data)), 0); consumeErr != nil {
		return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), fmt.Sprintf("budget consume denied: %v", consumeErr), consumeErr)
	}
	return nil
}

// finalize 는 SESE 단일 출구 지점으로, 성공 및 모든 실패 경로를 정규화하고
// 차단 감사 기록 및 최종 완료 감사/로그를 단 1곳에서 결정론적으로 마감한다.
func (g *gateway) finalize(ctx context.Context, state *pipelineState, tr pipeline.Trace) (*Result, error) {
	passed := make([]domain.Stage, len(tr.Passed))
	for i, id := range tr.Passed {
		passed[i] = domain.Stage(id)
	}
	if runErr := tr.Err; runErr != nil {
		reason := domain.ReasonFromError(runErr, domain.ReasonInternalError)
		exitCode := domain.ExitCodeFromError(runErr, domain.ExitCodeForReason(reason))
		failedStage := domain.Stage(tr.Failed)

		// 단일 출구 차단 감사 기록 (precommit_audit 단계 감사 실패 시 중복 기록 시도 방지).
		// 감사 없이 거부를 끝내지 않는다: 기록 실패 시 AUDIT_LOG_FAILED(15)로 마감하되 거부 결론은 유지한다.
		details := runErr.Error()
		if failedStage != domain.StagePrecommitAudit {
			if auditErr := g.logEvent(state, failedStage, false, reason, runErr.Error(), ""); auditErr != nil {
				g.obs.OnError(ctx, state.traceID, "failed to record block audit event",
					observe.Attr{Key: "error", Value: auditErr.Error()},
				)
				details = fmt.Sprintf("%s; block audit failed: %s", runErr.Error(), auditErr.Error())
				reason = domain.ReasonAuditLogFailed
				exitCode = domain.ExitAuditFailure
			}
		}

		g.obs.OnExecutionEnd(ctx, state.traceID, false,
			observe.Attr{Key: "stage", Value: string(failedStage)},
			observe.Attr{Key: "reason", Value: string(reason)},
			observe.Attr{Key: "exit_code", Value: int(exitCode)},
			observe.Attr{Key: "subject", Value: state.subject},
			observe.Attr{Key: "agent_id", Value: state.subject},
			observe.Attr{Key: "caller_id", Value: state.callerID},
		)

		return &Result{
			Allowed:  false,
			ExitCode: exitCode,
			Stage:    failedStage,
			Reason:   reason,
			Details:  details,
			Subject:  state.subject,
			TokenJTI: state.tokenJTI,
			SafePath: state.safePath,
			Passed:   passed,
		}, nil
	}

	// 실행(execute) 또는 정산(settle) 이 마지막으로 통과한 단계다.
	lastStage := passed[len(passed)-1]
	res := &Result{
		Allowed:    true,
		ExitCode:   domain.ExitSuccess,
		Stage:      domain.StageExecute,
		Reason:     domain.ReasonAuthorized,
		Details:    "operation successfully authorized and executed",
		Subject:    state.subject,
		TokenJTI:   state.tokenJTI,
		SafePath:   state.safePath,
		Data:       state.out.Data,
		BytesRead:  state.out.BytesRead,
		BytesWrote: state.out.BytesWrote,
		Passed:     passed,
	}

	// 정상 실행 완료 감사 기록
	if auditErr := g.logEvent(state, lastStage, true, domain.ReasonAuthorized, "file I/O execution completed", domain.DataDigest(res.Data)); auditErr != nil {
		g.obs.OnError(ctx, state.traceID, "failed to record completion audit event",
			observe.Attr{Key: "error", Value: auditErr.Error()},
		)
	}

	g.obs.OnExecutionEnd(ctx, state.traceID, true,
		observe.Attr{Key: "resource", Value: state.resource},
		observe.Attr{Key: "subject", Value: state.subject},
		observe.Attr{Key: "agent_id", Value: state.subject},
		observe.Attr{Key: "caller_id", Value: state.callerID},
		observe.Attr{Key: "bytes_read", Value: res.BytesRead},
		observe.Attr{Key: "bytes_wrote", Value: res.BytesWrote},
	)

	return res, nil
}

// logEvent 는 Zero Leakage 원칙에 따라 서명된 Bearer 원본 토큰은 일체 기록하지 않고,
// TokenJTI, Subject(AgentID), CallerID(위임 계보), 경로, 액션, 성공 여부만 감사 로그에 기록한다.
func (g *gateway) logEvent(state *pipelineState, stage domain.Stage, success bool, reason domain.Reason, details, resultHash string) error {
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
		Timestamp:  g.clock.Now().UTC(),
		TraceID:    state.traceID,
		Step:       stepName,
		Stage:      string(stage),
		Actor:      state.subject,
		AgentID:    state.subject,
		Action:     actionName,
		Resource:   state.resource,
		Decision:   decisionLabel(success, reason),
		Reason:     string(reason),
		TokenJTI:   state.tokenJTI,
		ArgHash:    state.argHash,
		ResultHash: resultHash,
		Success:    success,
		Metadata: map[string]interface{}{
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

// decisionLabel 은 감사 decision 값을 정한다. 종료 코드 18 계열 거부는 "ask" 로 기록한다.
func decisionLabel(success bool, reason domain.Reason) string {
	switch {
	case success:
		return "allow"
	case domain.ExitCodeForReason(reason) == domain.ExitApprovalRequired:
		return "ask"
	default:
		return "deny"
	}
}

// logApprovalConsumed 는 승인 소비 사실을 approval.consumed 로 기록한다 (원시 토큰은 기록하지 않는다).
func (g *gateway) logApprovalConsumed(state *pipelineState) error {
	return g.cfg.AuditWriter.Log(audit.Event{
		Timestamp: g.clock.Now().UTC(),
		TraceID:   state.traceID,
		Step:      "pep.approval_consume",
		Stage:     string(domain.StageApproval),
		Actor:     state.subject,
		AgentID:   state.subject,
		Action:    "approval.consumed",
		Resource:  state.resource,
		Decision:  "allow",
		Reason:    string(domain.ReasonAuthorized),
		TokenJTI:  state.tokenJTI,
		ArgHash:   state.argHash,
		Success:   true,
		Metadata: map[string]interface{}{
			"approval_id": state.approvalID,
		},
	})
}

// logBudgetConsumed 는 예산 차감 사실을 budget.consumed 로 기록한다 (표지만, 차감량·원시 토큰은 기록하지 않는다).
// Action 을 pep. 로 시작하게 쓰면 audit.NormalizeEvent 가 바꿔 버리므로 쓰지 않는다.
func (g *gateway) logBudgetConsumed(state *pipelineState) error {
	return g.cfg.AuditWriter.Log(audit.Event{
		Timestamp: g.clock.Now().UTC(),
		TraceID:   state.traceID,
		Step:      "pep.budget_consume",
		Stage:     string(domain.StageBudget),
		Actor:     state.subject,
		AgentID:   state.subject,
		Action:    "budget.consumed",
		Resource:  state.resource,
		Decision:  "allow",
		Reason:    string(domain.ReasonAuthorized),
		TokenJTI:  state.tokenJTI,
		ArgHash:   state.argHash,
		Success:   true,
	})
}

func extractReasonFromTokenError(err error) domain.Reason {
	if err == nil {
		return domain.ReasonAuthorized
	}
	return domain.ReasonFromError(err, domain.ReasonInvalidToken)
}
