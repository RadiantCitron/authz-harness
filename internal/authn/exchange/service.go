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
	return s
}

// Exchange 는 부모 토큰을 검증하고 권한 축소 불변식을 적용하여 자식 토큰을 발급한다.
func (s *ExchangeService) Exchange(ctx context.Context, req ExchangeRequest, auditCtx domain.AuditContext) (*ExchangeResult, error) {
	now := s.clock.Now().UTC()
	traceID := auditCtx.TraceID
	if traceID == "" {
		traceID = fmt.Sprintf("trace-%d", now.UnixNano())
	}
	actor := auditCtx.Actor
	if actor == "" {
		actor = req.ClientID
	}

	// 1. 클라이언트 인증
	clientInfo, err := s.clients.AuthenticateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		if aerr := s.recordAuditDenied(now, traceID, actor, req, "", domain.ReasonAuthnInvalidSecret, err.Error()); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
		}
		return nil, fmt.Errorf("client authentication failed: %w", err)
	}

	// 2. Child Subject 허용 여부 검사
	if strings.TrimSpace(req.ChildSubject) == "" {
		if aerr := s.recordAuditDenied(now, traceID, actor, req, "", domain.ReasonInvalidToken, "child subject is required"); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
		}
		return nil, errors.New("child subject is required")
	}
	if !clientInfo.IsSubjectAllowed(req.ChildSubject) {
		err := fmt.Errorf("client %s is not authorized to request tokens for subject %s (%s)",
			req.ClientID, req.ChildSubject, domain.ReasonNoActiveGrant)
		if aerr := s.recordAuditDenied(now, traceID, actor, req, "", domain.ReasonNoActiveGrant, err.Error()); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
		}
		return nil, err
	}

	// 3. 부모 토큰 Gate 1 무결성 및 암호학적 검증
	// 교환 시 부모 토큰의 jti 를 즉시 소비(RecordReplay)하지 않고, 무결성/유효성만 검사한다.
	verifiedParent, err := s.verifier.VerifyToken(req.ParentToken, token.VerifyOptions{
		RecordReplay: false,
	}, auditCtx)
	if err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonInvalidToken)
		if aerr := s.recordAuditDenied(now, traceID, actor, req, "", reason, err.Error()); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
		}
		return nil, domain.NewError(reason, "exchange", "parent token verification failed", err)
	}

	parentClaims := verifiedParent.Claims

	// 3-1. 부모 및 위임 조상(act 사슬) Security Epoch 실시간 사전 검증 (SnapshotProvider 가 배선된 경우)
	if s.snapshots != nil {
		snap, snapErr := s.snapshots.GetSubjectSnapshot(ctx, parentClaims.Subject)
		if snapErr != nil || snap == nil {
			details := fmt.Sprintf("failed to query parent subject snapshot: %v", snapErr)
			if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, domain.ReasonInternalError, details); aerr != nil {
				return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
			}
			return nil, domain.NewError(domain.ReasonInternalError, "exchange", details, snapErr)
		}
		parentEpoch := domain.Epoch(parentClaims.Epoch)
		if parentEpoch < 1 {
			parentEpoch = 1
		}
		if parentEpoch != snap.CurrentEpoch {
			details := fmt.Sprintf("parent %q epoch (%d) does not match current epoch (%d)", parentClaims.Subject, parentEpoch, snap.CurrentEpoch)
			if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, domain.ReasonSubjectEpochRevoked, details); aerr != nil {
				return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
			}
			return nil, domain.NewError(domain.ReasonSubjectEpochRevoked, "exchange", details, nil)
		}
		for a := parentClaims.Actor; a != nil; a = a.Actor {
			if a.Epoch < 1 || snap.SubjectEpochs == nil || snap.SubjectEpochs.Get(a.Subject) != a.Epoch {
				details := fmt.Sprintf("ancestor %q epoch (%d) does not match current epoch", a.Subject, a.Epoch)
				if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, domain.ReasonSubjectEpochRevoked, details); aerr != nil {
					return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
				}
				return nil, domain.NewError(domain.ReasonSubjectEpochRevoked, "exchange", details, nil)
			}
		}
	}

	// 4. 축소 위임(Downscoping) 불변식 검증
	if err := s.validator.ValidateDownscope(&parentClaims, req.ChildSubject, req.Scope, req.TTL, now); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonTokenInsufficientScope)
		if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, reason, err.Error()); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
		}
		return nil, domain.NewError(reason, "exchange", "downscope validation failed", err)
	}

	// 4-1. 예산 정적 검사 및 원장 필수 확인 (예산이 관여할 때만)
	budgetInvolved := parentClaims.Budget != nil || req.Budget != nil
	if budgetInvolved {
		if err := ValidateBudgetDownscope(parentClaims.Budget, req.Budget); err != nil {
			reason := domain.ReasonFromError(err, domain.ReasonDelegationBudgetExceeded)
			if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, reason, err.Error()); aerr != nil {
				return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
			}
			return nil, domain.NewError(reason, "exchange", "budget downscope validation failed", err)
		}
		if s.budgets == nil {
			err := errors.New("budget ledger is not configured")
			if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, domain.ReasonInternalError, err.Error()); aerr != nil {
				return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
			}
			return nil, domain.NewError(domain.ReasonInternalError, "exchange", "budget exchange requires a budget ledger", err)
		}
	}

	// 5. act 체인 구성 및 깊이 계산
	// 부모 정보를 현재 act 로 지정하고 부모의 기존 act 체인을 중첩
	childActor := &domain.ActorClaim{
		Subject: parentClaims.Subject,
		JWTID:   parentClaims.JWTID,
		Epoch:   parentClaims.Epoch,
		Actor:   parentClaims.Actor,
	}
	childDepth := parentClaims.DelegationDepth + 1
	childEpoch := req.ChildEpoch
	if childEpoch == 0 {
		childEpoch = 1
	}

	aud := req.Audience
	if strings.TrimSpace(aud) == "" {
		aud = parentClaims.Audience
	}

	// 6. 자식 토큰 발급
	issueReq := token.IssueRequest{
		ClientID:        req.ClientID,
		ClientSecret:    req.ClientSecret,
		Subject:         req.ChildSubject,
		Scope:           req.Scope,
		Audience:        aud,
		TTL:             req.TTL,
		Epoch:           childEpoch,
		Actor:           childActor,
		DelegationDepth: childDepth,
		Budget:          req.Budget,
	}

	childResult, err := s.issuer.IssueToken(issueReq, token.IssueOptions{}, auditCtx)
	if err != nil {
		if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, domain.ReasonInvalidToken, err.Error()); aerr != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
		}
		return nil, fmt.Errorf("failed to issue child token: %w", err)
	}

	// 6-1. 원장 예약. 부모 엔트리가 없으면 자동 초기화하지 않고 거부하며, 실패한 자식 토큰은 반환하지 않는다.
	if budgetInvolved {
		if err := s.budgets.Reserve(parentClaims.JWTID, childResult.Claims.JWTID, *req.Budget, childResult.Claims.ExpiresAt); err != nil {
			reason := domain.ReasonFromError(err, domain.ReasonInternalError)
			if aerr := s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, reason, err.Error()); aerr != nil {
				return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange deny audit log", aerr)
			}
			return nil, domain.NewError(reason, "exchange", "budget reservation failed", err)
		}
	}

	// 7. Zero Leakage 감사 이벤트 기록: token.exchanged (원시 JWT 노출 배제)
	if s.auditWriter != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   traceID,
			Step:      "token.exchange",
			Actor:     actor,
			Action:    "token.exchanged",
			Decision:  "allow",
			Reason:    string(domain.ReasonAuthorized),
			Success:   true,
			Metadata: map[string]interface{}{
				"parent_jti":       parentClaims.JWTID,
				"parent_sub":       parentClaims.Subject,
				"child_jti":        childResult.Claims.JWTID,
				"child_sub":        childResult.Claims.Subject,
				"client_id":        req.ClientID,
				"scope":            childResult.Claims.Scope,
				"delegation_depth": childDepth,
				"child_epoch":      childEpoch,
				"parent_epoch":     parentClaims.Epoch,
				"expires_at":       childResult.Claims.ExpiresAt,
			},
		}
		if err := s.auditWriter.Log(auditEv); err != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "token_exchange", "failed to record exchange audit log", err)
		}
	}

	return &ExchangeResult{
		TokenString:     childResult.TokenString,
		Claims:          childResult.Claims,
		ParentJTI:       parentClaims.JWTID,
		DelegationDepth: childDepth,
	}, nil
}

func (s *ExchangeService) recordAuditDenied(now time.Time, traceID, actor string, req ExchangeRequest, parentJTI string, reason domain.Reason, details string) error {
	if s.auditWriter == nil {
		return nil
	}
	auditEv := audit.Event{
		Timestamp: now,
		TraceID:   traceID,
		Step:      "token.exchange",
		Actor:     actor,
		Action:    "token.exchange.deny",
		Decision:  "deny",
		Reason:    string(reason),
		Success:   false,
		Metadata: map[string]interface{}{
			"client_id":  req.ClientID,
			"child_sub":  req.ChildSubject,
			"parent_jti": parentJTI,
			"scope":      req.Scope,
			"reason":     string(reason),
			"details":    details,
		},
	}
	return s.auditWriter.Log(auditEv)
}
