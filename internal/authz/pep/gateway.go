package pep

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/domain"
	"authz-harness/internal/execguard"
	"authz-harness/internal/jail"
	"authz-harness/internal/netguard"
	"authz-harness/internal/observe"
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

	// StageReplay 는 PDP allow 직후 일회성 토큰의 jti 를 원자적으로 소비하는 단계다.
	StageReplay Stage = "gate2b_replay"

	// StageGate2cJail 은 Workspace Jail 경로 정규화 및 격리 경계 검증 단계다.
	StageGate2cJail Stage = "gate2c_jail"

	// StageApproval 은 PDP 가 지목한 승인을 원자적으로 소비하는 단계다 (Gate 2c 뒤, Budget 앞).
	StageApproval Stage = "stage3a_approval"

	// StageBudget 은 예산 토큰의 쓰기 사전 차감 단계다 (Gate 2c 뒤, Stage 4 앞).
	StageBudget Stage = "stage3b_budget"

	// Stage4Audit 은 Fail-Closed 사전 커밋 감사 로그 기록 단계다.
	Stage4Audit Stage = "stage4_audit"

	// Stage5FileIO 는 격리 파일 I/O 실행 단계다.
	Stage5FileIO Stage = "stage5_io"
)

// stageOrder 는 관문 단계의 정식 순서다. runPipeline 이 단계를 부르는 순서와 같아야 하며,
// 화면(cli)처럼 단계 순서가 필요한 곳은 자기 표를 만들지 않고 Stages 로 이 목록을 읽는다.
// 일치는 시험(TestStageOrder_*)이 강제한다.
var stageOrder = [...]Stage{
	StageGate0Input,
	StageGate1AuthN,
	StageGate2AuthZ,
	StageReplay,
	StageGate2cJail,
	StageApproval,
	StageBudget,
	Stage4Audit,
	Stage5FileIO,
}

// Stages 는 관문 단계의 정식 순서를 담은 복사본을 돌려준다. 호출자가 고쳐도 내부 목록은 바뀌지 않는다.
// 승인(StageApproval)·예산(StageBudget)처럼 조건부로 도는 단계도 포함하므로,
// 한 요청이 실제로 통과한 단계는 Result.Passed 로 확인한다.
func Stages() []Stage {
	out := make([]Stage, len(stageOrder))
	copy(out, stageOrder[:])
	return out
}

// NormalizeAction 은 사용자 입력 문자열을 표준 액션으로 바꾼다(domain.ParseAction 에 위임, read/write 별칭 허용).
func NormalizeAction(act string) (domain.Action, error) {
	return domain.ParseAction(act)
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
	RequireTraceID     bool          // true 인 경우 TraceID 누락 시 Gate 0 에서 즉각 차단 (E2E-28 검증용)
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
	// Passed 는 이 요청이 실제로 통과한 단계를 통과한 순서대로 담는다. 실패한 단계는 들어 있지 않다.
	// 조건부 단계(승인·예산)가 이 요청에 해당 없으면 빠져 있으므로, 화면은 순서를 추론하지 않고 이 기록을 읽는다.
	Passed []Stage `json:"passed_stages,omitempty"`
}

// Gateway 는 파일 I/O 요청에 대한 인가 집행 관문 인터페이스다.
type Gateway interface {
	// Execute 는 5단계 관문(AuthN -> PDP -> Jail -> Audit -> I/O)을 거쳐 파일 작업을 집행한다.
	Execute(ctx context.Context, req Request) (*Result, error)
}

// ApprovalConsumer 는 승인을 ID 로 찾아 재검증한 뒤 소비(삭제)하는 포트다.
type ApprovalConsumer interface {
	ConsumeApproval(id string, b domain.ApprovalBinding, now time.Time) error
}

// Config 는 Gateway 생성에 필요한 하위 컴포넌트 의존성 주입 구조체다.
type Config struct {
	Verifier         token.TokenVerifier // Layer 2A: Gate 1 Bearer 토큰 검증기
	PDP              pdp.Service         // Layer 2B: Gate 2 순수 인가 결정 엔진
	Jail             jail.Jail           // Layer 2C: Gate 2c 격리 파일 경계
	AuditWriter      audit.Writer        // Layer 1: 감사 로그 기록기
	Clock            domain.Clock        // 결정론적 가상 시계 주입
	Observer         observe.Observer    // 관측성 포트 주입 (미주입 시 NoopObserver, 항상 WrapSafe 적용)
	StageObserver    func(Stage)         // 선택: 단계 통과 직후 호출되는 관찰자(단위 시험 전용, BuildStack 은 배선하지 않음)
	ApprovalConsumer ApprovalConsumer    // 선택: 승인 소비기. 승인으로 허용된 요청인데 없으면 Fail-Closed(16)
	BudgetLedger     budget.Ledger       // 선택: 예산 토큰(Budget != nil) 집행용 원장. 없으면 예산 토큰은 Fail-Closed 거부
	NetGuard         *netguard.Guard     // 선택: net:fetch 가드. nil 이면 net:fetch 는 Gate 2c 에서 Fail-Closed(16)
	ExecRunner       *execguard.Runner   // 선택: exec:run 실행기. nil 이면 exec:run 은 Gate 2c 에서 Fail-Closed(16)
}

type gateway struct {
	cfg   Config
	clock domain.Clock
	obs   observe.Observer
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

	return &gateway{cfg: cfg, clock: clk, obs: observe.WrapSafe(cfg.Observer)}, nil
}

// pipelineState 는 파이프라인 진행 과정에서 점진적으로 채워지는 불변 실행 상태다.
type pipelineState struct {
	traceID     string
	resource    string
	argHash     string // 요청 데이터 지문(domain.DataDigest), 원문은 기록하지 않는다
	normAction  domain.Action
	subject     string
	tokenJTI    string
	callerID    string
	safePath    string
	fetchTarget netguard.Target // net:fetch Gate 0 정규화 결과
	failedStage Stage
	passed      []Stage   // 통과한 단계 기록 (runStage 가 fn 성공 시 추가, finalize 가 Result.Passed 로 복사)
	approvalID  string    // PDP 가 승인으로 allow 했을 때 소비할 승인 ID
	evalNow     time.Time // PDP 판정과 승인 소비에 쓰는 같은 시각

	// 예산 집행 상태 (환급용). 쓰기 사전 차감 성공 시에만 refundWriteBytes 가 채워진다.
	budgeted         bool
	consumed         bool
	refundWriteBytes int64
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
		argHash:  domain.DataDigest(req.Data),
	}

	res, err := g.runPipeline(ctx, req, state)
	return g.finalize(ctx, state, res, err)
}

// runStage 는 파이프라인 단계별 Before/After Around 계측 래퍼다.
func (g *gateway) runStage(ctx context.Context, state *pipelineState, stage Stage, fn func() error) error {
	start := g.clock.Now()
	g.obs.OnStageStart(ctx, state.traceID, string(stage),
		observe.Attr{Key: "resource", Value: state.resource},
		observe.Attr{Key: "subject", Value: state.subject},
	)

	err := fn()
	if err == nil {
		state.passed = append(state.passed, stage)
		if g.cfg.StageObserver != nil {
			g.cfg.StageObserver(stage)
		}
	}
	durationMs := g.clock.Now().Sub(start).Milliseconds()

	if err != nil {
		state.failedStage = stage
		reason := domain.ReasonFromError(err, domain.ReasonInternalError)
		g.obs.OnStageEnd(ctx, state.traceID, string(stage), false,
			observe.Attr{Key: "reason", Value: string(reason)},
			observe.Attr{Key: "duration_ms", Value: durationMs},
			observe.Attr{Key: "resource", Value: state.resource},
			observe.Attr{Key: "subject", Value: state.subject},
		)
		return err
	}

	g.obs.OnStageEnd(ctx, state.traceID, string(stage), true,
		observe.Attr{Key: "duration_ms", Value: durationMs},
		observe.Attr{Key: "resource", Value: state.resource},
		observe.Attr{Key: "subject", Value: state.subject},
	)
	return nil
}

// runPipeline 은 Gate 0부터 Stage 5까지 순차적으로 실행하며, 차단 시 표준 *domain.Error 를 반환한다.
func (g *gateway) runPipeline(ctx context.Context, req Request, state *pipelineState) (res *Result, err error) {
	// 사전 차감 이후 어느 단계든 실패하면 차감분을 환급한다. 환급 실패는 원래 거부 사유를 바꾸지 않는다.
	defer func() {
		if err != nil && state.consumed {
			g.refundBudget(ctx, state)
		}
	}()

	// 0. 기본 입력 인자 유효성 검증
	if err := g.runStage(ctx, state, StageGate0Input, func() error {
		if req.RequireTraceID && strings.TrimSpace(req.TraceID) == "" {
			return domain.NewError(domain.ReasonMissingTraceContext, string(StageGate0Input), "trace_id is required but missing", nil)
		}
		normAction, actErr := NormalizeAction(string(req.Action))
		if actErr != nil || state.resource == "" {
			return domain.NewError(domain.ReasonInvalidArguments, string(StageGate0Input), "action must be file:read, file:write, net:fetch or exec:run, and resource cannot be empty", actErr)
		}
		state.normAction = normAction
		if normAction == domain.ActionNetFetch {
			if len(req.Data) > 0 {
				return domain.NewError(domain.ReasonInvalidArguments, string(StageGate0Input), "net:fetch must not carry data", nil)
			}
			t, parseErr := netguard.ParseTarget(state.resource)
			if parseErr != nil {
				// 원문 URL(자격 정보·질의 포함 가능)이 감사에 남지 않게 지문만 기록한다.
				state.argHash = domain.DataDigest([]byte(state.resource))
				state.resource = "<invalid-url>"
				return domain.NewError(domain.ReasonEgressDenied, string(StageGate0Input), "net:fetch target rejected", parseErr)
			}
			state.resource = t.HostPort
			state.fetchTarget = t
			state.argHash = domain.DataDigest([]byte(t.URL))
		}
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
			RecordReplay:     false,
			CheckReplay:      true,
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
		if verifiedClaims.Claims.Budget != nil {
			state.budgeted = true
			if g.cfg.BudgetLedger == nil {
				return domain.NewError(domain.ReasonInternalError, string(StageGate1AuthN), "budget token presented but no budget ledger is configured (fail-closed)", nil)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 2: Gate 2 - Pure PDP Authorization
	if err := g.runStage(ctx, state, StageGate2AuthZ, func() error {
		state.evalNow = g.clock.Now().UTC().Add(req.ClockOffset)
		pdpReq := pdp.Request{
			Subject:      state.subject,
			Action:       state.normAction,
			Resource:     state.resource,
			Epoch:        domain.Epoch(verifiedClaims.Claims.Epoch),
			TokenScope:   verifiedClaims.Claims.Scope,
			RequireScope: true, // 토큰 기반 PEP 실행은 항상 Scope 검증 필수
			Actor:        verifiedClaims.Claims.Actor,
			TraceID:      state.traceID,
			TokenJTI:     state.tokenJTI,
			ArgHash:      state.argHash,
			Now:          state.evalNow,
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
		state.approvalID = decision.ApprovalID
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 2b: PDP allow 직후 jti 소비 (ask·deny 에서는 소비하지 않아 승인 뒤 같은 토큰으로 재시도할 수 있다)
	if err := g.runStage(ctx, state, StageReplay, func() error {
		return g.cfg.Verifier.ConsumeReplay(verifiedClaims.Claims, domain.AuditContext{TraceID: state.traceID, Actor: "pep-gateway"})
	}); err != nil {
		return nil, err
	}

	// Stage 3: Gate 2c - Workspace Jail Boundary Verification
	if err := g.runStage(ctx, state, StageGate2cJail, func() error {
		switch state.normAction {
		case domain.ActionNetFetch:
			if g.cfg.NetGuard == nil {
				return domain.NewError(domain.ReasonInternalError, string(StageGate2cJail), "net guard is not configured (fail-closed)", nil)
			}
			if checkErr := g.cfg.NetGuard.Check(state.resource); checkErr != nil {
				return domain.NewError(domain.ReasonFromError(checkErr, domain.ReasonEgressDenied), string(StageGate2cJail), fmt.Sprintf("Gate 2c egress denied: %v", checkErr), checkErr)
			}
		case domain.ActionExecRun:
			if g.cfg.ExecRunner == nil {
				return domain.NewError(domain.ReasonInternalError, string(StageGate2cJail), "exec runner is not configured (fail-closed)", nil)
			}
			if valErr := execguard.Validate(state.resource, string(req.Data)); valErr != nil {
				return domain.NewError(domain.ReasonFromError(valErr, domain.ReasonExecNotAllowed), string(StageGate2cJail), fmt.Sprintf("Gate 2c exec rejected: %v", valErr), valErr)
			}
		default:
			forWrite := (state.normAction == domain.ActionFileWrite)
			safePath, jailErr := g.cfg.Jail.ResolvePath(state.resource, forWrite)
			if jailErr != nil {
				jailReason := jail.ReasonFromError(jailErr)
				return domain.NewError(jailReason, string(StageGate2cJail), fmt.Sprintf("Gate 2c jail path containment violated: %v", jailErr), jailErr)
			}
			state.safePath = safePath
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Stage 3a: 승인 소비 (PDP 가 승인으로 allow 한 경우만). 소비한 승인은 이후 단계가 실패해도 되돌리지 않는다.
	if state.approvalID != "" {
		if err := g.runStage(ctx, state, StageApproval, func() error {
			if g.cfg.ApprovalConsumer == nil {
				return domain.NewError(domain.ReasonInternalError, string(StageApproval), "approval required but no approval consumer is configured (fail-closed)", nil)
			}
			binding := domain.ApprovalBinding{Subject: state.subject, Action: state.normAction, Resource: state.resource, TokenJTI: state.tokenJTI, ArgHash: state.argHash}
			if consumeErr := g.cfg.ApprovalConsumer.ConsumeApproval(state.approvalID, binding, state.evalNow); consumeErr != nil {
				return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), string(StageApproval), fmt.Sprintf("approval consume denied: %v", consumeErr), consumeErr)
			}
			// 잠금은 이미 풀렸다. 감사 실패는 Fail-Closed(승인은 이미 소멸).
			if auditErr := g.logApprovalConsumed(state); auditErr != nil {
				return domain.NewError(domain.ReasonAuditLogFailed, string(StageApproval), fmt.Sprintf("approval audit failure (fail-closed): %v", auditErr), auditErr)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	// Stage 3b: Budget - 쓰기 사전 차감 (예산 토큰만, 읽기는 바이트 수를 알 수 없어 Stage 5 에서 사후 차감)
	if state.budgeted && (state.normAction == domain.ActionFileWrite || state.normAction == domain.ActionExecRun) {
		if err := g.runStage(ctx, state, StageBudget, func() error {
			n := int64(len(req.Data))
			if consumeErr := g.cfg.BudgetLedger.Consume(state.tokenJTI, 1, 0, n); consumeErr != nil {
				return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), string(StageBudget), fmt.Sprintf("budget consume denied: %v", consumeErr), consumeErr)
			}
			state.consumed = true
			state.refundWriteBytes = n
			return nil
		}); err != nil {
			return nil, err
		}
	}

	// Stage 4: Pre-Commit Audit Verification (Fail-Closed, Zero Side-Effects on Failure)
	if err := g.runStage(ctx, state, Stage4Audit, func() error {
		if req.InjectAuditFailure {
			return domain.NewError(domain.ReasonAuditLogFailed, string(Stage4Audit), "injected audit failure simulation (fail-closed)", nil)
		}
		auditErr := g.logEvent(state, Stage4Audit, true, domain.ReasonAuthorized, "pre-commit audit check passed", "")
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
			if state.budgeted {
				// 읽기 사후 차감: 실패하면 데이터를 결과에 담지 않고 버린다 (읽기는 부작용 없음)
				if consumeErr := g.cfg.BudgetLedger.Consume(state.tokenJTI, 1, int64(len(data)), 0); consumeErr != nil {
					return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), string(Stage5FileIO), fmt.Sprintf("budget consume denied: %v", consumeErr), consumeErr)
				}
			}
			res.Data = data
			res.BytesRead = len(data)

		case domain.ActionFileWrite:
			if writeErr := g.cfg.Jail.WriteFile(state.resource, req.Data); writeErr != nil {
				return domain.NewError(domain.ReasonInternalError, string(Stage5FileIO), fmt.Sprintf("pep: failed to write file in jail: %v", writeErr), writeErr)
			}
			res.BytesWrote = len(req.Data)

		case domain.ActionNetFetch:
			data, fetchErr := g.cfg.NetGuard.Fetch(ctx, state.fetchTarget)
			if fetchErr != nil {
				return domain.NewError(domain.ReasonFromError(fetchErr, domain.ReasonInternalError), string(Stage5FileIO), fmt.Sprintf("pep: net fetch failed: %v", fetchErr), fetchErr)
			}
			if state.budgeted {
				if consumeErr := g.cfg.BudgetLedger.Consume(state.tokenJTI, 1, int64(len(data)), 0); consumeErr != nil {
					return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), string(Stage5FileIO), fmt.Sprintf("budget consume denied: %v", consumeErr), consumeErr)
				}
			}
			res.Data = data
			res.BytesRead = len(data)

		case domain.ActionExecRun:
			// 실행이 시작되면 실패해도 환급하지 않는다(부작용이 이미 났을 수 있다).
			state.consumed = false
			out, runErr := g.cfg.ExecRunner.Run(ctx, state.resource, string(req.Data))
			if runErr != nil {
				return domain.NewError(domain.ReasonFromError(runErr, domain.ReasonInternalError), string(Stage5FileIO), fmt.Sprintf("pep: exec failed: %v", runErr), runErr)
			}
			if state.budgeted {
				if consumeErr := g.cfg.BudgetLedger.Consume(state.tokenJTI, 0, int64(len(out)), 0); consumeErr != nil {
					return domain.NewError(domain.ReasonFromError(consumeErr, domain.ReasonInternalError), string(Stage5FileIO), fmt.Sprintf("budget consume denied: %v", consumeErr), consumeErr)
				}
			}
			res.Data = out
			res.BytesRead = len(out)
		}

		finalRes = res
		return nil
	}); err != nil {
		return nil, err
	}

	return finalRes, nil
}

// refundBudget 은 사전 차감된 쓰기 예산을 원장에 환급한다. 실패는 운영 로그에만 남긴다.
func (g *gateway) refundBudget(ctx context.Context, state *pipelineState) {
	if err := g.cfg.BudgetLedger.Refund(state.tokenJTI, 1, 0, state.refundWriteBytes); err != nil {
		g.obs.OnError(ctx, state.traceID, "failed to refund budget",
			observe.Attr{Key: "token_jti", Value: state.tokenJTI},
			observe.Attr{Key: "error", Value: err.Error()},
		)
	}
}

// finalize 는 SESE 단일 출구 지점으로, 성공 및 모든 실패 경로를 정규화하고
// 차단 감사 기록 및 최종 완료 감사/로그를 단 1곳에서 결정론적으로 마감한다.
func (g *gateway) finalize(ctx context.Context, state *pipelineState, res *Result, runErr error) (*Result, error) {
	if runErr != nil {
		reason := domain.ReasonFromError(runErr, domain.ReasonInternalError)
		exitCode := domain.ExitCodeFromError(runErr, domain.ExitCodeForReason(reason))
		failedStage := state.failedStage

		// 단일 출구 차단 감사 기록 (Stage4 감사 실패 시 중복 기록 시도 방지).
		// 감사 없이 거부를 끝내지 않는다: 기록 실패 시 AUDIT_LOG_FAILED(15)로 마감하되 거부 결론은 유지한다.
		details := runErr.Error()
		if failedStage != Stage4Audit {
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
			Passed:   append([]Stage(nil), state.passed...),
		}, nil
	}

	res.Passed = append([]Stage(nil), state.passed...)

	// 정상 실행 완료 감사 기록
	if auditErr := g.logEvent(state, Stage5FileIO, true, domain.ReasonAuthorized, "file I/O execution completed", domain.DataDigest(res.Data)); auditErr != nil {
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
func (g *gateway) logEvent(state *pipelineState, stage Stage, success bool, reason domain.Reason, details, resultHash string) error {
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
			"stage":       string(StageApproval),
			"approval_id": state.approvalID,
		},
	})
}

func extractReasonFromTokenError(err error) domain.Reason {
	if err == nil {
		return domain.ReasonAuthorized
	}
	return domain.ReasonFromError(err, domain.ReasonInvalidToken)
}
