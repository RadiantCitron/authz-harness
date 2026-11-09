// Package exchange 는 RFC 8693 OAuth 2.0 Token Exchange 표준 기반의 축소 위임(Downscoping) 파이프라인 서비스를 구현한다.
//
// [핵심 인가 아키텍처 및 8단계 컨베이어 벨트 파이프라인]
// 1. 단일 진입점 및 SESE(Single Entry Single Exit) 보장:
//   - Exchange(ctx, req, auditCtx) 는 TC-060-04-E 에 명시된 대로 오직 맨 끝 return 1개로만 종료한다.
//   - 모든 성공/거부 감사 이벤트와 에러 포장은 finalize() 단일 마감 메서드로 통합 수렴한다.
//
// 2. 8단계 축소 위임 검문소 (domain.ExchangeStages):
//   - 01_client_auth: 요청 클라이언트(대리인) 자격증명 인증 (crypto/subtle.ConstantTimeCompare)
//   - 02_delegation_subject: 클라이언트의 자식 주체 위임 권한 검증 (clientInfo.IsSubjectAllowed)
//   - 03_parent_token: 부모 Bearer 토큰 무결성·서명·만료 검증 (단, 부모 jti 리플레이 소비는 하지 않음)
//   - 04_lineage_epoch: 부모 및 조상(act 사슬) 전체의 Security Epoch 실시간 대조 (PIP 스냅샷)
//   - 05_downscope: 5대 축소 불변식 정적 검증 (동일 주체 금지, 스코프 부분집합, TTL 단축 등)
//   - 06_budget_downscope: 예산 상한 축소 정적 검증 및 원장(Ledger) 배선 여부 확인
//   - 07_token_issue: 조상 사슬(act)이 연결된 신규 자식 RFC 9068 Access Token 발급 및 Zone A 서명
//   - 08_budget_reserve: 자식 발급 성공 후 부모 예산 원장에서 자식 한도 원자적 차감/예약 (정산 단계)
//
// 3. DIP(의존성 역전 원칙) 배선:
//   - internal/app/builder.go 의 BuildStack 에서 TokenIssuer, TokenVerifier, ClientRegistry,
//     DownscopeValidator, audit.Writer, domain.Clock, budget.Ledger, domain.SnapshotProvider 를 주입받아 조립된다.
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
	// ClientID 는 토큰 교환을 요청하는 위임 대리인 클라이언트 ID 다.
	ClientID string

	// ClientSecret 은 요청 클라이언트의 자격증명 비밀값이다.
	ClientSecret string

	// ParentToken 은 권한을 위임하고자 하는 원본 부모 토큰 (Base64URL JWT) 이다.
	ParentToken string

	// ChildSubject 는 위임받을 신규 자식 주체 식별자다 (예: "worker-01").
	ChildSubject string

	// Scope 는 자식에게 부여할 축소된 권한 스코프다. 부모 스코프의 진부분집합이어야 한다.
	Scope string

	// Audience 는 자식 토큰의 대상 리소스 서버 식별자다 (비어있으면 부모 Audience 상속).
	Audience string

	// TTL 은 자식 토큰의 유효 수명이다. 부모 잔여 수명보다 짧거나 같아야 한다.
	TTL time.Duration

	// Budget 은 자식에게 할당할 호출 횟수 및 I/O 바이트 예산 상한이다. 부모 예산이 있으면 필수다.
	Budget *domain.Budget

	// ChildEpoch 는 자식 주체의 보안 세대 번호다 (0이면 1). 틀리면 PEP 의 PDP 가 거부한다(Fail-Closed).
	ChildEpoch domain.Epoch
}

// ExchangeResult 는 RFC 8693 토큰 교환 성공 시 반환되는 결과 묶음이다.
type ExchangeResult struct {
	// TokenString 은 서명된 신규 자식 JWT 문자열이다.
	TokenString string `json:"token"`

	// Claims 는 자식 토큰에 포함된 정규화된 클레임 구조체다.
	Claims domain.TokenClaims `json:"claims"`

	// ParentJTI 는 권한을 위임해 준 직전 부모 토큰의 고유 식별자다.
	ParentJTI string `json:"parent_jti"`

	// DelegationDepth 는 현재 자식 토큰의 위임 깊이다 (부모 depth + 1).
	DelegationDepth int `json:"delegation_depth"`
}

// Service 는 RFC 8693 Token Exchange 오케스트레이션 서비스의 DIP 추상 인터페이스다.
type Service interface {
	// Exchange 는 부모 토큰을 검증하고 권한 축소 불변식을 적용하여 자식 토큰을 발급한다.
	Exchange(ctx context.Context, req ExchangeRequest, auditCtx domain.AuditContext) (*ExchangeResult, error)
}

// ExchangeService 는 Service 인터페이스의 8단계 파이프라인 구현체다.
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
}

// Option 은 ExchangeService 의 선택적 의존성 주입을 위한 함수형 옵션(Functional Option)이다.
type Option func(*ExchangeService)

// WithBudgetLedger 는 예산 예약에 쓸 원장(budget.Ledger)을 주입한다. 없으면 예산 교환은 Fail-Closed 로 거부된다.
func WithBudgetLedger(l budget.Ledger) Option {
	return func(s *ExchangeService) { s.budgets = l }
}

// WithSnapshotProvider 는 토큰 교환 시점에 부모 및 위임 조상(act 사슬)의 최신 Security Epoch 를
// 실시간 대조하기 위한 스냅샷 공급자(domain.SnapshotProvider / PIP)를 주입한다.
func WithSnapshotProvider(sp domain.SnapshotProvider) Option {
	return func(s *ExchangeService) { s.snapshots = sp }
}

// NewExchangeService 는 ExchangeService 인스턴스를 생성하고 8단계 컨베이어 벨트를 초기화한다.
// DIP 원칙에 따라 issuer, verifier, clients, validator, auditWriter, clock 을 주입받는다.
func NewExchangeService(
	issuer token.TokenIssuer,
	verifier token.TokenVerifier,
	clients token.ClientRegistry,
	validator DownscopeValidator,
	auditWriter audit.Writer,
	clock domain.Clock,
	opts ...Option,
) (*ExchangeService, error) {
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
	eng, err := pipeline.New[exchangeCall](s.assemble(), nil)
	if err != nil {
		return nil, fmt.Errorf("exchange: failed to assemble pipeline: %w", err)
	}
	s.engine = eng
	return s, nil
}

// exchangeCall 은 8단계 교환 파이프라인이 진행되면서 단계별로 상태를 누적해 나가는 컨텍스트 구조체다.
type exchangeCall struct {
	req      ExchangeRequest
	auditCtx domain.AuditContext
	now      time.Time // Exchange 입구 시각
	traceID  string    // Exchange 입구 생성 추적 ID
	actor    string    // Exchange 입구 행위자

	clientInfo     *token.ClientInfo  // Stage 01(client_auth)에서 채워짐
	parentClaims   domain.TokenClaims // Stage 03(parent_token)에서 채워짐
	parentJTI      string             // parent_token 이 통과해야 채워짐. 그 전의 거부 감사에는 빈 값이 남음
	budgetInvolved bool               // Stage 03(parent_token)에서 부모/자식 예산 관여 여부 판별
	childEpoch     domain.Epoch       // Stage 07(token_issue)에서 확정
	childDepth     int                // Stage 07(token_issue)에서 계산
	child          *token.IssueResult // Stage 07(token_issue)에서 발급 완료
}

// denial 은 파이프라인 검문 실패 시 감사 사유(domain.Reason)와 호출자 반환용 에러(error)를 쌍으로 캡슐화한다.
type denial struct {
	reason  domain.Reason
	details string
	ret     error
}

func (d *denial) Error() string { return d.ret.Error() }
func (d *denial) Unwrap() error { return d.ret }

// step 은 pipeline.Step[exchangeCall] 생성 헬퍼 함수다.
func step(id domain.Stage, kind domain.StageKind, applies func(*exchangeCall) bool, run func(context.Context, *exchangeCall) error) pipeline.Step[exchangeCall] {
	s := pipeline.Step[exchangeCall]{ID: string(id), Kind: pipeline.Kind(kind), Run: run}
	if applies != nil {
		s.Applies = applies
	}
	return s
}

// assemble 은 8단계 토큰 교환 파이프라인의 검문소 조립 목록을 구성한다.
// 순서와 성격은 domain.ExchangeStages() 와 정확히 일치해야 하며 아키텍처 가드레일 테스트가 이를 강제한다.
// 교환 파이프라인은 Saga Compensate 를 쓰지 않는다: 마지막 단계(예산 예약) 실패 시 자식 토큰을 미발급 폐기하므로 롤백할 앞선 I/O 소비가 없다.
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

// Exchange 는 RFC 8693 Token Exchange 의 최상위 진입점이다.
// [보안 가드레일: TC-060-04-E] 단일 진입점-단일 출구(Single-Entry Single-Exit, SESE) 원칙을 준수하여
// 함수의 출구는 맨 끝 return s.finalize(...) 하나뿐이다.
func (s *ExchangeService) Exchange(ctx context.Context, req ExchangeRequest, auditCtx domain.AuditContext) (res *ExchangeResult, err error) {
	now := s.clock.Now().UTC()
	traceID := auditCtx.TraceID
	if traceID == "" {
		traceID = fmt.Sprintf("trace-%d", now.UnixNano())
	}
	actor := auditCtx.Actor
	if actor == "" {
		actor = req.ClientID
	}
	c := &exchangeCall{req: req, auditCtx: auditCtx, now: now, traceID: traceID, actor: actor}
	return s.finalize(c, s.engine.Run(ctx, c))
}

// finalize 는 교환 파이프라인의 단일 종착 마감(Single Exit) 메서드다.
// 파이프라인 실행 결과(pipeline.Trace)를 분석하여 거부 감사 기록, AUDIT_LOG_FAILED 승격 처리,
// 성공 감사 기록(Zero Leakage)을 한곳에서 원자적으로 수행한다.
func (s *ExchangeService) finalize(c *exchangeCall, tr pipeline.Trace) (*ExchangeResult, error) {
	if tr.Err != nil {
		var d *denial
		if !errors.As(tr.Err, &d) {
			d = &denial{reason: domain.ReasonInternalError, details: tr.Err.Error(), ret: tr.Err}
		}
		if aerr := s.recordAuditDenied(c, domain.Stage(tr.Failed), d.reason, d.details); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "failed to record exchange deny audit log", aerr)
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
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "failed to record exchange audit log", err)
		}
	}

	return &ExchangeResult{
		TokenString:     c.child.TokenString,
		Claims:          c.child.Claims,
		ParentJTI:       c.parentClaims.JWTID,
		DelegationDepth: c.childDepth,
	}, nil
}

// Stage 01. client_auth: 대리인 클라이언트 자격증명 인증 (crypto/subtle.ConstantTimeCompare)
func (s *ExchangeService) clientAuth(ctx context.Context, c *exchangeCall) error {
	info, err := s.clients.AuthenticateClient(c.req.ClientID, c.req.ClientSecret)
	if err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonAuthnInvalidSecret)
		return &denial{reason, err.Error(), domain.NewError(reason, "client authentication failed", err)}
	}
	c.clientInfo = info
	return nil
}

// Stage 02. delegation_subject: 요청 클라이언트가 해당 자식 주체(ChildSubject) 명의로 토큰을 요청할 수 있는지 검사
func (s *ExchangeService) delegationSubject(ctx context.Context, c *exchangeCall) error {
	if strings.TrimSpace(c.req.ChildSubject) == "" {
		msg := "child subject is required"
		return &denial{domain.ReasonInvalidToken, msg, domain.NewError(domain.ReasonInvalidToken, msg, nil)}
	}
	if !c.clientInfo.IsSubjectAllowed(c.req.ChildSubject) {
		msg := fmt.Sprintf("client %s is not authorized to request tokens for subject %s (%s)",
			c.req.ClientID, c.req.ChildSubject, domain.ReasonNoActiveGrant)
		return &denial{domain.ReasonNoActiveGrant, msg, domain.NewError(domain.ReasonNoActiveGrant, msg, nil)}
	}
	return nil
}

// Stage 03. parent_token: 부모 토큰 무결성·암호학적 서명 검증.
// 교환 시에는 부모 토큰이 살아있음을 검증하되 jti 를 리플레이 소비(RecordReplay: false)하지 않는다.
func (s *ExchangeService) parentToken(ctx context.Context, c *exchangeCall) error {
	verified, err := s.verifier.VerifyToken(c.req.ParentToken, token.VerifyOptions{RecordReplay: false}, c.auditCtx)
	if err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonInvalidToken)
		return &denial{reason, err.Error(), domain.NewError(reason, "parent token verification failed", err)}
	}
	c.parentClaims = verified.Claims
	c.parentJTI = c.parentClaims.JWTID
	c.budgetInvolved = c.parentClaims.Budget != nil || c.req.Budget != nil
	return nil
}

// Stage 04. lineage_epoch: 부모 및 조상(act 사슬) 전체의 Security Epoch 실시간 대조 (PIP 스냅샷 배선 시)
func (s *ExchangeService) lineageEpoch(ctx context.Context, c *exchangeCall) error {
	p := &c.parentClaims
	snap, snapErr := s.snapshots.GetSubjectSnapshot(ctx, p.Subject)
	if snapErr != nil || snap == nil {
		details := fmt.Sprintf("failed to query parent subject snapshot: %v", snapErr)
		return &denial{domain.ReasonInternalError, details, domain.NewError(domain.ReasonInternalError, details, snapErr)}
	}
	if reason, badAncestor := snap.ValidateLineageEpoch(p.Subject, p.Epoch, p.Actor); reason != "" {
		parentEpoch := domain.Epoch(p.Epoch)
		if parentEpoch < 1 {
			parentEpoch = 1
		}
		var details string
		if badAncestor != nil {
			details = fmt.Sprintf("ancestor %q epoch (%d) does not match current epoch", badAncestor.Subject, badAncestor.Epoch)
		} else if parentEpoch != snap.CurrentEpoch {
			details = fmt.Sprintf("parent %q epoch (%d) does not match current epoch (%d)", p.Subject, parentEpoch, snap.CurrentEpoch)
		}
		return &denial{reason, details, domain.NewError(reason, details, nil)}
	}
	return nil
}

// Stage 05. downscope: 5대 축소 위임(Downscoping) 불변식 정적 검증
func (s *ExchangeService) downscope(ctx context.Context, c *exchangeCall) error {
	if err := s.validator.ValidateDownscope(&c.parentClaims, c.req.ChildSubject, c.req.Scope, c.req.TTL, c.now); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonTokenInsufficientScope)
		return &denial{reason, err.Error(), domain.NewError(reason, "downscope validation failed", err)}
	}
	return nil
}

// Stage 06. budget_downscope: 자식 예산 상한 정적 축소 검사 및 예산 원장(Ledger) 존재 필수 확인
func (s *ExchangeService) budgetDownscope(ctx context.Context, c *exchangeCall) error {
	if err := ValidateBudgetDownscope(c.parentClaims.Budget, c.req.Budget); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonDelegationBudgetExceeded)
		return &denial{reason, err.Error(), domain.NewError(reason, "budget downscope validation failed", err)}
	}
	if s.budgets == nil {
		err := errors.New("budget ledger is not configured")
		return &denial{domain.ReasonInternalError, err.Error(), domain.NewError(domain.ReasonInternalError, "budget exchange requires a budget ledger", err)}
	}
	return nil
}

// Stage 07. token_issue: 선대 계보(act) 사슬 연결 및 Zone A 개인키 기반 신규 자식 토큰 발급
func (s *ExchangeService) tokenIssue(ctx context.Context, c *exchangeCall) error {
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
		// 발급기가 도메인 사유를 달아 주면 그대로 기록한다. 감사 사유와 돌려주는 종료 코드가 어긋나지 않게 한다.
		reason := domain.ReasonFromError(err, domain.ReasonInvalidToken)
		return &denial{reason, err.Error(), domain.NewError(reason, fmt.Sprintf("failed to issue child token: %v", err), err)}
	}
	c.child = res
	return nil
}

// Stage 08. budget_reserve: 예산 원장 예약. 자식 jti 가 발급 뒤에야 생기므로 성격은 소비가 아니라 정산이다(ADR 0007 4장).
// 부모 엔트리가 없으면 자동 초기화하지 않고 거부하며, 실패한 자식 토큰은 반환하지 않는다.
func (s *ExchangeService) budgetReserve(ctx context.Context, c *exchangeCall) error {
	if err := s.budgets.Reserve(c.parentClaims.JWTID, c.child.Claims.JWTID, *c.req.Budget, c.child.Claims.ExpiresAt); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonInternalError)
		return &denial{reason, err.Error(), domain.NewError(reason, "budget reservation failed", err)}
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
