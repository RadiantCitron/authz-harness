package exchange

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
	"authz-harness/internal/pipeline"
)

// ExchangeRequest 는 RFC 8693 Token Exchange 요청 명세다.
type ExchangeRequest struct {
	ClientID     string
	ClientSecret string
	ParentToken  string
	ChildSubject string
	Scope        string
	Audience     string
	TTL          time.Duration
	Budget       *domain.Budget // 자식 예산 상한. 부모 예산이 있으면 필수.
	ChildEpoch   domain.Epoch   // 자식 주체의 Epoch (0이면 1). 틀리면 PEP 의 PDP 가 거부한다(Fail-Closed).
}

// ExchangeResult 는 토큰 교환 결과다.
type ExchangeResult struct {
	TokenString     string             `json:"token"`
	Claims          domain.TokenClaims `json:"claims"`
	ParentJTI       string             `json:"parent_jti"`
	DelegationDepth int                `json:"delegation_depth"`
}

// Service 는 RFC 8693 Token Exchange 오케스트레이션 서비스 인터페이스다.
type Service interface {
	Exchange(ctx context.Context, req ExchangeRequest, auditCtx domain.AuditContext) (*ExchangeResult, error)
}

// ExchangeService 는 Service 구현체다.
type ExchangeService struct {
	issuer      token.TokenIssuer
	verifier    token.TokenVerifier
	clients     token.ClientRegistry
	validator   DownscopeValidator
	auditWriter audit.Writer
	clock       domain.Clock
	budgets     budget.Ledger
	snapshots   domain.SnapshotProvider
	engine      *pipeline.Engine[exchangeCall]
	engineErr   error
}

// Option 은 ExchangeService 의 선택적 의존성 주입 옵션이다.
type Option func(*ExchangeService)

// WithBudgetLedger 는 예산 예약에 쓸 원장을 주입한다. 없으면 예산 교환은 Fail-Closed 로 거부된다.
func WithBudgetLedger(l budget.Ledger) Option {
	return func(s *ExchangeService) { s.budgets = l }
}

// WithSnapshotProvider 는 토큰 교환 시점에 부모 및 위임 조상(act 사슬)의 최신 Security Epoch 를
// 실시간 대조하기 위한 스냅샷 공급자(PIP)를 주입한다.
func WithSnapshotProvider(sp domain.SnapshotProvider) Option {
	return func(s *ExchangeService) { s.snapshots = sp }
}

// NewExchangeService 는 ExchangeService 인스턴스를 생성한다.
func NewExchangeService(
	issuer token.TokenIssuer,
	verifier token.TokenVerifier,
	clients token.ClientRegistry,
	validator DownscopeValidator,
	auditWriter audit.Writer,
	clock domain.Clock,
	opts ...Option,
) *ExchangeService {
	if clock == nil {
		clock = domain.RealClock{}
	}
	if validator == nil {
		validator = NewDownscopeValidator()
	}
	if clients == nil {
		clients = token.NewInMemoryClientRegistry()
	}
	s := &ExchangeService{
		issuer:      issuer,
		verifier:    verifier,
		clients:     clients,
		validator:   validator,
		auditWriter: auditWriter,
		clock:       clock,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.engine, s.engineErr = pipeline.New[exchangeCall](s.assemble(), nil)
	return s
}

// exchangeCall 은 파이프라인이 단계마다 채워 가는 한 번의 교환 상태다. 필드마다 채우는 단계를 밝힌다.
type exchangeCall struct {
	ctx      context.Context
	req      ExchangeRequest
	auditCtx domain.AuditContext
	now      time.Time // Exchange
	traceID  string    // Exchange
	actor    string    // Exchange

	clientInfo     *token.ClientInfo // client_auth
	parentClaims   domain.TokenClaims
	parentJTI      string // parent_token 이 통과해야 채워진다. 그 전의 거부 감사에는 빈 값이 남는다
	budgetInvolved bool   // parent_token
	childEpoch     domain.Epoch
	childDepth     int
	child          *token.IssueResult // token_issue
}

// denial 은 단계 실패의 감사 사유와 호출자에게 돌려줄 오류를 함께 나른다.
// 둘이 단계마다 다르고 일부는 *domain.Error 가 아니어서, 마감이 그대로 돌려준다.
type denial struct {
	reason  domain.Reason
	details string
	ret     error
}

func (d *denial) Error() string { return d.ret.Error() }
func (d *denial) Unwrap() error { return d.ret }

// kindOf 는 도메인 성격을 엔진 성격으로 바꾼다. pipeline 은 domain 을 모르므로 변환 표는 조립 쪽에 둔다.
var kindOf = map[domain.StageKind]pipeline.Kind{
	domain.KindCheck:   pipeline.Check,
	domain.KindDecide:  pipeline.Decide,
	domain.KindConsume: pipeline.Consume,
	domain.KindRecord:  pipeline.Record,
	domain.KindExecute: pipeline.Execute,
	domain.KindSettle:  pipeline.Settle,
}

func step(id domain.Stage, kind domain.StageKind, applies func(*exchangeCall) bool, run func(*exchangeCall) error) pipeline.Step[exchangeCall] {
	s := pipeline.Step[exchangeCall]{ID: string(id), Kind: kindOf[kind], Run: func(_ context.Context, c *exchangeCall) error { return run(c) }}
	if applies != nil {
		s.Applies = applies
	}
	return s
}

// assemble 은 교환의 조립 목록이다. 순서와 성격은 domain.ExchangeStages() 와 같아야 하며 시험이 강제한다.
// 교환은 Compensate 를 쓰지 않는다: 마지막 단계(예약)의 실패를 되돌릴 앞선 소비가 없다.
func (s *ExchangeService) assemble() []pipeline.Step[exchangeCall] {
	hasSnapshots := func(*exchangeCall) bool { return s.snapshots != nil }
	hasBudget := func(c *exchangeCall) bool { return c.budgetInvolved }
	return []pipeline.Step[exchangeCall]{
		step(domain.StageClientAuth, domain.KindCheck, nil, s.clientAuth),
		step(domain.StageDelegationSubject, domain.KindCheck, nil, s.delegationSubject),
		step(domain.StageParentToken, domain.KindCheck, nil, s.parentToken),
		step(domain.StageLineageEpoch, domain.KindCheck, hasSnapshots, s.lineageEpoch),
		step(domain.StageDownscope, domain.KindDecide, nil, s.downscope),
		step(domain.StageBudgetDownscope, domain.KindCheck, hasBudget, s.budgetDownscope),
		step(domain.StageTokenIssue, domain.KindExecute, nil, s.tokenIssue),
		step(domain.StageBudgetReserve, domain.KindSettle, hasBudget, s.budgetReserve),
	}
}

// Exchange 는 부모 토큰을 검증하고 권한 축소 불변식을 적용하여 자식 토큰을 발급한다.
func (s *ExchangeService) Exchange(ctx context.Context, req ExchangeRequest, auditCtx domain.AuditContext) (*ExchangeResult, error) {
	if s.engineErr != nil {
		return nil, domain.NewError(domain.ReasonInternalError, "exchange", "exchange pipeline assembly failed (fail-closed)", s.engineErr)
	}
	now := s.clock.Now().UTC()
	traceID := auditCtx.TraceID
	if traceID == "" {
		traceID = fmt.Sprintf("trace-%d", now.UnixNano())
	}
	actor := auditCtx.Actor
	if actor == "" {
		actor = req.ClientID
	}
	c := &exchangeCall{ctx: ctx, req: req, auditCtx: auditCtx, now: now, traceID: traceID, actor: actor}
	return s.finalize(c, s.engine.Run(ctx, c))
}

// finalize 는 단일 마감이다. 거부 감사, AUDIT_LOG_FAILED 승격, 성공 감사를 한 곳에서 처리한다.
func (s *ExchangeService) finalize(c *exchangeCall, tr pipeline.Trace) (*ExchangeResult, error) {
	if tr.Err != nil {
		var d *denial
		if !errors.As(tr.Err, &d) {
			d = &denial{reason: domain.ReasonInternalError, details: tr.Err.Error(), ret: tr.Err}
		}
		if aerr := s.recordAuditDenied(c, domain.Stage(tr.Failed), d.reason, d.details); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
		}
		return nil, d.ret
	}

	// Zero Leakage 감사 이벤트 기록: token.exchanged (원시 JWT 노출 배제). Stage 는 마지막 통과 단계다.
	if s.auditWriter != nil {
		auditEv := audit.Event{
			Timestamp: c.now,
			TraceID:   c.traceID,
			Step:      "token.exchange",
			Stage:     tr.Passed[len(tr.Passed)-1],
			Actor:     c.actor,
			Action:    "token.exchanged",
			Decision:  "allow",
			Reason:    string(domain.ReasonAuthorized),
			Success:   true,
			Metadata: map[string]interface{}{
				"parent_jti":       c.parentClaims.JWTID,
				"parent_sub":       c.parentClaims.Subject,
				"child_jti":        c.child.Claims.JWTID,
				"child_sub":        c.child.Claims.Subject,
				"client_id":        c.req.ClientID,
				"scope":            c.child.Claims.Scope,
				"delegation_depth": c.childDepth,
				"child_epoch":      c.childEpoch,
				"parent_epoch":     c.parentClaims.Epoch,
				"expires_at":       c.child.Claims.ExpiresAt,
			},
		}
		if err := s.auditWriter.Log(auditEv); err != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange audit log", err)
		}
	}

	return &ExchangeResult{
		TokenString:     c.child.TokenString,
		Claims:          c.child.Claims,
		ParentJTI:       c.parentClaims.JWTID,
		DelegationDepth: c.childDepth,
	}, nil
}

// client_auth: 클라이언트 인증
func (s *ExchangeService) clientAuth(c *exchangeCall) error {
	info, err := s.clients.AuthenticateClient(c.req.ClientID, c.req.ClientSecret)
	if err != nil {
		return &denial{domain.ReasonAuthnInvalidSecret, err.Error(), fmt.Errorf("client authentication failed: %w", err)}
	}
	c.clientInfo = info
	return nil
}

// delegation_subject: 자식 주체 허용 여부
func (s *ExchangeService) delegationSubject(c *exchangeCall) error {
	if strings.TrimSpace(c.req.ChildSubject) == "" {
		err := errors.New("child subject is required")
		return &denial{domain.ReasonInvalidToken, "child subject is required", err}
	}
	if !c.clientInfo.IsSubjectAllowed(c.req.ChildSubject) {
		err := fmt.Errorf("client %s is not authorized to request tokens for subject %s (%s)",
			c.req.ClientID, c.req.ChildSubject, domain.ReasonNoActiveGrant)
		return &denial{domain.ReasonNoActiveGrant, err.Error(), err}
	}
	return nil
}

// parent_token: 부모 토큰 무결성·암호학적 검증. 교환 시 부모 jti 를 소비(RecordReplay)하지 않고 유효성만 본다.
func (s *ExchangeService) parentToken(c *exchangeCall) error {
	verified, err := s.verifier.VerifyToken(c.req.ParentToken, token.VerifyOptions{RecordReplay: false}, c.auditCtx)
	if err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonInvalidToken)
		return &denial{reason, err.Error(), domain.NewError(reason, "exchange", "parent token verification failed", err)}
	}
	c.parentClaims = verified.Claims
	c.parentJTI = c.parentClaims.JWTID
	c.budgetInvolved = c.parentClaims.Budget != nil || c.req.Budget != nil
	return nil
}

// lineage_epoch: 부모 및 위임 조상(act 사슬) Security Epoch 실시간 대조 (SnapshotProvider 가 배선된 경우)
func (s *ExchangeService) lineageEpoch(c *exchangeCall) error {
	p := &c.parentClaims
	snap, snapErr := s.snapshots.GetSubjectSnapshot(c.ctx, p.Subject)
	if snapErr != nil || snap == nil {
		details := fmt.Sprintf("failed to query parent subject snapshot: %v", snapErr)
		return &denial{domain.ReasonInternalError, details, domain.NewError(domain.ReasonInternalError, "exchange", details, snapErr)}
	}
	parentEpoch := domain.Epoch(p.Epoch)
	if parentEpoch < 1 {
		parentEpoch = 1
	}
	if parentEpoch != snap.CurrentEpoch {
		details := fmt.Sprintf("parent %q epoch (%d) does not match current epoch (%d)", p.Subject, parentEpoch, snap.CurrentEpoch)
		return &denial{domain.ReasonSubjectEpochRevoked, details, domain.NewError(domain.ReasonSubjectEpochRevoked, "exchange", details, nil)}
	}
	for a := p.Actor; a != nil; a = a.Actor {
		if a.Epoch < 1 || snap.SubjectEpochs == nil || snap.SubjectEpochs.Get(a.Subject) != a.Epoch {
			details := fmt.Sprintf("ancestor %q epoch (%d) does not match current epoch", a.Subject, a.Epoch)
			return &denial{domain.ReasonSubjectEpochRevoked, details, domain.NewError(domain.ReasonSubjectEpochRevoked, "exchange", details, nil)}
		}
	}
	return nil
}

// downscope: 축소 위임(Downscoping) 불변식
func (s *ExchangeService) downscope(c *exchangeCall) error {
	if err := s.validator.ValidateDownscope(&c.parentClaims, c.req.ChildSubject, c.req.Scope, c.req.TTL, c.now); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonTokenInsufficientScope)
		return &denial{reason, err.Error(), domain.NewError(reason, "exchange", "downscope validation failed", err)}
	}
	return nil
}

// budget_downscope: 예산 정적 검사 및 원장 필수 확인 (예산이 관여할 때만)
func (s *ExchangeService) budgetDownscope(c *exchangeCall) error {
	if err := ValidateBudgetDownscope(c.parentClaims.Budget, c.req.Budget); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonDelegationBudgetExceeded)
		return &denial{reason, err.Error(), domain.NewError(reason, "exchange", "budget downscope validation failed", err)}
	}
	if s.budgets == nil {
		err := errors.New("budget ledger is not configured")
		return &denial{domain.ReasonInternalError, err.Error(), domain.NewError(domain.ReasonInternalError, "exchange", "budget exchange requires a budget ledger", err)}
	}
	return nil
}

// token_issue: act 체인 구성과 자식 토큰 발급
func (s *ExchangeService) tokenIssue(c *exchangeCall) error {
	p := &c.parentClaims
	childActor := &domain.ActorClaim{Subject: p.Subject, JWTID: p.JWTID, Epoch: p.Epoch, Actor: p.Actor}
	c.childDepth = p.DelegationDepth + 1
	c.childEpoch = c.req.ChildEpoch
	if c.childEpoch == 0 {
		c.childEpoch = 1
	}
	aud := c.req.Audience
	if strings.TrimSpace(aud) == "" {
		aud = p.Audience
	}
	res, err := s.issuer.IssueToken(token.IssueRequest{
		ClientID:        c.req.ClientID,
		ClientSecret:    c.req.ClientSecret,
		Subject:         c.req.ChildSubject,
		Scope:           c.req.Scope,
		Audience:        aud,
		TTL:             c.req.TTL,
		Epoch:           c.childEpoch,
		Actor:           childActor,
		DelegationDepth: c.childDepth,
		Budget:          c.req.Budget,
	}, token.IssueOptions{}, c.auditCtx)
	if err != nil {
		return &denial{domain.ReasonInvalidToken, err.Error(), fmt.Errorf("failed to issue child token: %w", err)}
	}
	c.child = res
	return nil
}

// budget_reserve: 원장 예약. 자식 jti 가 발급 뒤에야 생기므로 성격은 소비가 아니라 정산이다(ADR 0007 4장).
// 부모 엔트리가 없으면 자동 초기화하지 않고 거부하며, 실패한 자식 토큰은 반환하지 않는다.
func (s *ExchangeService) budgetReserve(c *exchangeCall) error {
	if err := s.budgets.Reserve(c.parentClaims.JWTID, c.child.Claims.JWTID, *c.req.Budget, c.child.Claims.ExpiresAt); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonInternalError)
		return &denial{reason, err.Error(), domain.NewError(reason, "exchange", "budget reservation failed", err)}
	}
	return nil
}

// recordAuditDenied 는 거부 감사의 유일한 기록 지점이다. Stage 는 실패한 단계다.
func (s *ExchangeService) recordAuditDenied(c *exchangeCall, stage domain.Stage, reason domain.Reason, details string) error {
	if s.auditWriter == nil {
		return nil
	}
	return s.auditWriter.Log(audit.Event{
		Timestamp: c.now,
		TraceID:   c.traceID,
		Step:      "token.exchange",
		Stage:     string(stage),
		Actor:     c.actor,
		Action:    "token.exchange.deny",
		Decision:  "deny",
		Reason:    string(reason),
		Success:   false,
		Metadata: map[string]interface{}{
			"client_id":  c.req.ClientID,
			"child_sub":  c.req.ChildSubject,
			"parent_jti": c.parentJTI,
			"scope":      c.req.Scope,
			"reason":     string(reason),
			"details":    details,
		},
	})
}
