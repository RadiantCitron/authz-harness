// Package pep 은 10단계 파이프라인 검문소로 구성된 인가 집행 관문(Policy Enforcement Point)을 제공한다 (ADR 0008, ADR 0007).
//
// [PEP 게이트웨이의 핵심 아키텍처 원칙]
// 1. 선언적 1차원 평면 파이프라인 (pipeline.Engine[Call]):
//    - 미들웨어 체인처럼 함수가 함수를 부르는 재귀 호출을 배제하고, 1차원 평면 배열 루프로 10개 검문소를 순차 강제한다.
//    - 컨베이어 벨트 순서:
//      1. input (검사) ➔ 2. authn (검사) ➔ 3. authz (결정) ➔ 4. boundary (검사) ➔ 5. replay (소비)
//      ➔ 6. approval (소비) ➔ 7. budget (소비) ➔ 8. precommit_audit (기록) ➔ 9. execute (실행) ➔ 10. settle (정산)
// 2. Fail-Closed & Early Exit:
//    - 어느 한 단계라도 에러를 반환하면 그 즉시 파이프라인 루프를 중단하고 후속 단계(실행 등)를 일절 수행하지 않는다.
// 3. Saga LIFO 역순 보상 (Compensate / Refund):
//    - 7단계 budget 에서 토큰 예산이 선차감된 후 8단계 precommit_audit 등 후속 단계가 실패하면,
//      파이프라인 엔진이 스택을 거꾸로 풀며 g.refund() 를 호출하여 차감된 예산을 즉시 환불/복구한다.
// 4. SESE (Single-Entry Single-Exit) 단일 출구 아키텍처:
//    - Execute 메서드는 오직 마지막 finalize 함수 한 곳에서만 결과를 마감하며,
//      성공 및 차단에 대한 감사 로그(audit.jsonl) 기록과 관측 통지를 누락 없이 결정론적으로 수행한다.
// 5. Zero Leakage 감사 추적:
//    - 서명된 Bearer 원본 토큰(eyJ...)은 감사 로그에 일절 남기지 않고 오직 jti 와 클레임 요약만 기록한다.
//
// [중앙 조립처 크로스체킹 (Cross-Referencing)]
// - 조립처: internal/app/builder.go 의 BuildStack
// - 파이프라인 엔진: internal/pipeline/pipeline.go
// - 도메인 단계 규약: internal/domain/stage.go 의 PEPStages()
// - 작동원리 해설서: docs/작동원리/007-파이프라인_컨베이어벨트_양파패킷_DIP_관측_해설.md
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

// Request 는 PEP 에 도구 작업 집행을 요청하는 매개변수 명세다.
type Request struct {
	// Token 은 클라이언트가 제시한 RFC 9068 Bearer Access Token (JWT) 원문이다.
	Token string

	// Action 은 수행하려는 도구 행위다 (file:read, file:write, net:fetch, exec:run).
	Action domain.Action

	// Resource 는 접근 대상 리소스 경로 또는 URL 이다 (상대 경로 권장).
	Resource string

	// Data 는 쓰기 요청(file:write) 또는 실행 인자(exec:run)로 전달할 바이트 데이터다.
	Data []byte

	// InjectAuditFailure 는 Pre-Commit 감사 기록 실패를 시뮬레이션하기 위한 결함 주입 스위치다 (E2E 테스트 전용).
	InjectAuditFailure bool

	// ExpectedAudience 는 토큰 수신자 기대값이다 (기본값: "authz-harness").
	ExpectedAudience string

	// ExpectedSubject 는 선택적 주체 기대값 검증 문자열이다.
	ExpectedSubject string

	// ClockOffset 은 가상 시간 시뮬레이션을 위한 시계 오프셋이다.
	ClockOffset time.Duration

	// AllowNegativeClockOffset 이 false(기본) 이면 음수 ClockOffset 을 input 단계에서 즉시 거부한다 (만료 토큰 부활 방지).
	// nbf 이전 시각을 일부러 시뮬레이션하는 하네스 시나리오만 켠다. CLI·서브프로세스 워커는 노출하지 않는다.
	AllowNegativeClockOffset bool

	// TraceID 는 트랜잭션 상관 추적 식별자다 (미지정 시 자동 생성).
	TraceID string

	// RequireTraceID 가 true 면 TraceID 누락 시 input 단계에서 즉각 차단한다 (E2E-28 검증용).
	RequireTraceID bool
}

// Result 는 PEP 관문 집행 결과 및 단계별 판정 세부 정보다.
type Result struct {
	// Allowed 는 요청이 10단계를 모두 통과하여 성공적으로 집행되었는지 여부다.
	Allowed bool `json:"allowed"`

	// ExitCode 는 프로세스 종료 시 반환할 표준 종료 코드다 (ExitSuccess=0, 11~18).
	ExitCode domain.ExitCode `json:"exit_code"`

	// Stage 는 실패가 발생한 단계 식별자다 (모두 성공 시 빈 문자열 "").
	Stage domain.Stage `json:"failed_stage,omitempty"`

	// Reason 은 판정 사유 코드다 (AUTHORIZED, TOKEN_EXPIRED, NO_ACTIVE_GRANT 등).
	Reason domain.Reason `json:"reason"`

	// Details 는 오류 또는 판정에 대한 세부 설명이다.
	Details string `json:"details,omitempty"`

	// Subject 는 인가된 주체 식별자다.
	Subject string `json:"subject,omitempty"`

	// TokenJTI 는 요청에 사용된 토큰의 jti 다.
	TokenJTI string `json:"token_jti,omitempty"`

	// SafePath 는 Jail 격리 검증을 통과한 안전한 절대 경로다.
	SafePath string `json:"safe_path,omitempty"`

	// BytesRead 는 읽어들인 바이트 수다.
	BytesRead int `json:"bytes_read,omitempty"`

	// BytesWrote 는 기록한 바이트 수다.
	BytesWrote int `json:"bytes_wrote,omitempty"`

	// Data 는 읽기 요청 성공 시 반환되는 파일 내용이다 (JSON 직렬화 제외).
	Data []byte `json:"-"`

	// Passed 는 이 요청이 실제로 성공적으로 통과한 단계들을 순서대로 담는다.
	// 조건부 단계(승인, 예산)가 해당 없어서 건너뛴 경우 이 목록에서 빠지므로 화면 UI 는 이 기록을 그대로 렌더링한다.
	Passed []domain.Stage `json:"passed_stages,omitempty"`
}

// Gateway 는 파일 I/O 및 도구 요청에 대한 인가 집행 관문 인터페이스다 (DIP 포트).
type Gateway interface {
	// Execute 는 10단계 파이프라인을 거쳐 요청을 안전하게 집행하고 결과를 반환한다.
	// 아키텍처 가드레일에 따라 SESE 단일 출구 규약을 준수한다.
	Execute(ctx context.Context, req Request) (*Result, error)
}

// ApprovalConsumer 는 6단계 approval 검문소에서 승인 티켓을 ID 로 찾아 재검증한 뒤 원장에서 소비(삭제)하는 포트다.
type ApprovalConsumer interface {
	ConsumeApproval(id string, b domain.ApprovalBinding, now time.Time) error
}

// Config 는 Gateway 인스턴스 생성에 필요한 모든 하위 의존성을 주입받는 구성체다 (DIP).
type Config struct {
	Verifier         token.TokenVerifier // Layer 2A: 2단계 authn Bearer 토큰 검증기
	PDP              pdp.Service         // Layer 2B: 3단계 authz 순수 인가 결정 엔진
	Jail             jail.Jail           // Layer 2C: 4단계 boundary 파일시스템 격리 경계
	AuditWriter      audit.Writer        // Layer 1: 8단계 precommit_audit 및 사후 감사 기록기
	Clock            domain.Clock        // 결정론적 가상 시계 주입 포트
	Observer         observe.Observer    // 관측성 포트 주입 (미주입 시 NoopObserver, 항상 WrapSafe 적용)
	StageObserver    func(domain.Stage)  // 선택: 단계 통과 직후 호출되는 관찰자 (단위 시험 전용)
	ApprovalConsumer ApprovalConsumer    // 선택: 6단계 승인 소비기. 승인으로 허용된 요청인데 없으면 Fail-Closed(16)
	BudgetLedger     domain.BudgetLedger // 선택: 7단계 예산 집행용 원장. 없으면 예산 토큰은 Fail-Closed(16) 거부
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
// 필수 의존성(Verifier, PDP, Jail, AuditWriter) 누락 시 즉시 생성을 거부한다 (Fail-Closed).
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

	// observe.WrapSafe 로 관측기를 감싸 관측 계층의 패닉이 메인 인가 파이프라인으로 전파되지 않도록 격리
	g := &gateway{cfg: cfg, clock: clk, obs: observe.WrapSafe(cfg.Observer)}
	eng, err := pipeline.New[Call](g.assemble(), stageHook{g})
	if err != nil {
		return nil, fmt.Errorf("pep: assemble pipeline: %w", err)
	}
	g.engine = eng
	return g, nil
}

// pipelineState 는 파이프라인 컨베이어 벨트를 타며 각 단계에 의해 점진적으로 채워지는 실행 상태 패킷이다 (ADR 0008).
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

// step 은 단일 파이프라인 단계를 생성하는 헬퍼 함수다.
func step(id domain.Stage, kind domain.StageKind, applies func(*Call) bool, run func(context.Context, *Call) error) pipeline.Step[Call] {
	s := pipeline.Step[Call]{ID: string(id), Kind: pipeline.Kind(kind), Run: run}
	if applies != nil {
		s.Applies = func(c *Call) bool { return applies(c) }
	}
	return s
}

// assemble 은 PEP 10단계 검문소의 공식 조립 목록을 구성한다.
//
// [순서와 성격 불변식]:
// 순서와 성격은 domain.PEPStages() 와 완전히 동일해야 하며, TestStageOrder 가 이를 정적으로 강제한다.
// 7단계 budget 단계에는 장애 발생 시 차감된 예산을 복구하는 LIFO 역순 보상(Compensate = g.refund)이 장착된다.
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

// approved 는 6단계 approval 의 조건부 실행 술어다 (PDP 가 승인 ID 를 발급했을 때만 실행).
func approved(c *Call) bool { return c.st.approvalID != "" }

// budgeted 는 7단계 budget 의 조건부 실행 술어다 (토큰에 Budget 클레임이 포함되었을 때만 실행).
func budgeted(c *Call) bool { return c.st.budgeted }

// postCharged 는 10단계 settle 의 조건부 실행 술어다 (예산 토큰이면서 도구가 사후 정산을 요구할 때만 실행).
func postCharged(c *Call) bool {
	return c.st.budgeted && c.st.tool.BudgetPlan(c).PostCharge
}

// Execute 는 파이프라인 엔진을 구동하고 단일 출구(finalize)에서 모든 감사와 결과를 일원화 마감한다.
//
// [아키텍처 가드레일: TC-060-04 (SESE 단일 출구 규약)]
// Execute 함수 내에는 오직 단 1개의 return 문(return g.finalize(...))만 존재해야 하며,
// 중간 return 을 일절 금지하여 감사 누락이나 불완전한 상태 종료를 원천 차단한다.
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

// stageHook 은 파이프라인 엔진의 Hook 규약을 구현하여 단계별 시작/종료를 계측하고 관측기에 통지한다.
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

// input (1단계): 기본 입력 인자 유효성 검증과 도구별 입력 정규화
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

// authn (2단계): 제시된 Bearer 토큰의 서명, 유효 기간, 수신처(aud), 주체(sub) 검증
func (g *gateway) authn(_ context.Context, c *Call) error {
	st, req := c.st, c.req
	expectedAud := req.ExpectedAudience
	if expectedAud == "" {
		expectedAud = domain.DefaultAudience
	}
	auditCtx := domain.AuditContext{TraceID: st.traceID, Actor: "pep-gateway"}
	vc, verifyErr := g.cfg.Verifier.VerifyToken(req.Token, token.VerifyOptions{
		ExpectedAudience:         expectedAud,
		ExpectedSubject:          req.ExpectedSubject,
		RecordReplay:             false,
		CheckReplay:              true,
		ClockOffset:              req.ClockOffset,
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

// authz (3단계): PDP 인가 결정 엔진을 호출하여 활성 권한(Grant), 주체 Epoch, 스코프 대조
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

// boundary (4단계): 도구별 경계 검사 (Jail 경로 격리, Egress allow-list, Exec allow-list)
func (g *gateway) boundary(_ context.Context, c *Call) error {
	return c.st.tool.CheckBoundary(c)
}

// replay (5단계): 모든 선행 검사를 통과한 뒤 jti 를 소비한다.
// deny, ask, 경계 거부 등 이전 단계 실패 시에는 소비하지 않아 동일 토큰으로 안전하게 재시도할 수 있다.
func (g *gateway) replay(_ context.Context, c *Call) error {
	return g.cfg.Verifier.ConsumeReplay(c.st.claims.Claims, domain.AuditContext{TraceID: c.st.traceID, Actor: "pep-gateway"})
}

// approval (6단계): 승인 소비. 소비된 승인은 이후 단계가 실패하더라도 되돌리지 않는다 (소멸).
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

// budget (7단계): 예산 토큰의 호출 1회와 쓰기 바이트를 실행 전에 차감한다.
// 이후 단계(감사, 실행 등)가 실패하면 Compensate(g.refund)가 보상한다.
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

// refund 는 budget 단계의 LIFO 역순 보상(Compensate) 콜백이다.
// 환급 실패 시 원래의 거부 사유를 덮어쓰지 않고 운영 로그에만 안전하게 남긴다.
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

// precommit_audit (8단계): 실제 도구 실행 직전, 감사 로그(audit.jsonl) 기록 가능 여부를 최종 확정한다.
// Fail-Closed 보안 원칙에 따라 이 단계가 실패하면 도구 실행(execute)은 절대 호출되지 않는다.
func (g *gateway) precommitAudit(_ context.Context, c *Call) error {
	if c.req.InjectAuditFailure {
		return domain.NewError(domain.ReasonAuditLogFailed, "injected audit failure simulation (fail-closed)", nil)
	}
	if auditErr := g.logEvent(c.st, domain.StagePrecommitAudit, true, domain.ReasonAuthorized, "pre-commit audit check passed", ""); auditErr != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("audit writer failure (fail-closed): %v", auditErr), auditErr)
	}
	return nil
}

// execute (9단계): 도구 실행 집행
func (g *gateway) execute(ctx context.Context, c *Call) error {
	if !c.st.tool.BudgetPlan(c).RefundAfterStart {
		// 실행이 시작되면 실패해도 환급하지 않는다 (부작용이 이미 났을 수 있다).
		c.st.consumed = false
	}
	out, err := c.st.tool.Execute(ctx, c)
	if err != nil {
		return err
	}
	c.st.out = out
	return nil
}

// settle (10단계): 도구 실행 완료 후 실제 발생한 출력 바이트를 정산한다.
// 정산 실패 시 결과를 반환하지 않고 에러로 마감한다.
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
