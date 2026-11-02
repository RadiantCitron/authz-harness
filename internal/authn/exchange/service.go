package exchange

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
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
}

// NewExchangeService 는 ExchangeService 인스턴스를 생성한다.
func NewExchangeService(
	issuer token.TokenIssuer,
	verifier token.TokenVerifier,
	clients token.ClientRegistry,
	validator DownscopeValidator,
	auditWriter audit.Writer,
	clock domain.Clock,
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
	return &ExchangeService{
		issuer:      issuer,
		verifier:    verifier,
		clients:     clients,
		validator:   validator,
		auditWriter: auditWriter,
		clock:       clock,
	}
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
		s.recordAuditDenied(now, traceID, actor, req, "", domain.ReasonAuthnInvalidSecret, err.Error())
		return nil, fmt.Errorf("client authentication failed: %w", err)
	}

	// 2. Child Subject 허용 여부 검사
	if strings.TrimSpace(req.ChildSubject) == "" {
		s.recordAuditDenied(now, traceID, actor, req, "", domain.ReasonInvalidToken, "child subject is required")
		return nil, errors.New("child subject is required")
	}
	if !clientInfo.IsSubjectAllowed(req.ChildSubject) {
		err := fmt.Errorf("client %s is not authorized to request tokens for subject %s (%s)",
			req.ClientID, req.ChildSubject, domain.ReasonNoActiveGrant)
		s.recordAuditDenied(now, traceID, actor, req, "", domain.ReasonNoActiveGrant, err.Error())
		return nil, err
	}

	// 3. 부모 토큰 Gate 1 무결성 및 암호학적 검증
	// 교환 시 부모 토큰의 jti 를 즉시 소비(RecordReplay)하지 않고, 무결성/유효성만 검사한다.
	verifiedParent, err := s.verifier.VerifyToken(req.ParentToken, token.VerifyOptions{
		RecordReplay: false,
	}, auditCtx)
	if err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonInvalidToken)
		s.recordAuditDenied(now, traceID, actor, req, "", reason, err.Error())
		return nil, domain.NewError(reason, "exchange", "parent token verification failed", err)
	}

	parentClaims := verifiedParent.Claims

	// 4. 축소 위임(Downscoping) 불변식 검증
	if err := s.validator.ValidateDownscope(&parentClaims, req.ChildSubject, req.Scope, req.TTL, now); err != nil {
		reason := domain.ReasonFromError(err, domain.ReasonTokenInsufficientScope)
		s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, reason, err.Error())
		return nil, domain.NewError(reason, "exchange", "downscope validation failed", err)
	}

	// 5. act 체인 구성 및 깊이 계산
	// 부모 정보를 현재 act 로 지정하고 부모의 기존 act 체인을 중첩
	childActor := &domain.ActorClaim{
		Subject: parentClaims.Subject,
		JWTID:   parentClaims.JWTID,
		Actor:   parentClaims.Actor,
	}
	childDepth := parentClaims.DelegationDepth + 1

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
		Epoch:           parentClaims.Epoch,
		Actor:           childActor,
		DelegationDepth: childDepth,
	}

	childResult, err := s.issuer.IssueToken(issueReq, token.IssueOptions{}, auditCtx)
	if err != nil {
		s.recordAuditDenied(now, traceID, actor, req, parentClaims.JWTID, domain.ReasonInvalidToken, err.Error())
		return nil, fmt.Errorf("failed to issue child token: %w", err)
	}

	// 7. Zero Leakage 감사 이벤트 기록: token.exchanged (원시 JWT 노출 배제)
	if s.auditWriter != nil {
		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   traceID,
			Step:      "030-exchange",
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
				"expires_at":       childResult.Claims.ExpiresAt,
			},
		}
		_ = s.auditWriter.Log(auditEv)
	}

	return &ExchangeResult{
		TokenString:     childResult.TokenString,
		Claims:          childResult.Claims,
		ParentJTI:       parentClaims.JWTID,
		DelegationDepth: childDepth,
	}, nil
}

func (s *ExchangeService) recordAuditDenied(now time.Time, traceID, actor string, req ExchangeRequest, parentJTI string, reason domain.Reason, details string) {
	if s.auditWriter == nil {
		return
	}
	auditEv := audit.Event{
		Timestamp: now,
		TraceID:   traceID,
		Step:      "030-exchange",
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
	_ = s.auditWriter.Log(auditEv)
}
