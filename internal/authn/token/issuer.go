package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/domain"
)

// IssueRequest 는 RFC 9068 Access Token 발급 요청 파라미터다.
type IssueRequest struct {
	ClientID        string
	ClientSecret    string
	Subject         string
	Scope           string
	Audience        string
	TTL             time.Duration
	Epoch           domain.Epoch
	Actor           *domain.ActorClaim
	DelegationDepth int
}

// IssueOptions 는 결함 주입(Fault Injection) 등을 위한 발급 옵션이다.
type IssueOptions struct {
	TamperSignature bool
	TamperAlgNone   bool
	TamperTyp       string // 비어있지 않으면 typ 헤더를 해당 값으로 교체 (예: "JWT")
}

// IssueResult 는 토큰 발급 결과다.
type IssueResult struct {
	TokenString string             `json:"token"`
	Claims      domain.TokenClaims `json:"claims"`
	KeyID       string             `json:"kid"`
}

// TokenIssuer 인터페이스다.
type TokenIssuer interface {
	IssueToken(req IssueRequest, opts IssueOptions, auditCtx domain.AuditContext) (*IssueResult, error)
}

// JWTHeader 는 JOSE Header 구조체다.
type JWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

// Service 는 토큰 발급 및 관리를 담당하는 서비스다.
type Service struct {
	keyMgr      keys.KeyManager
	clients     ClientRegistry
	auditWriter audit.Writer
	clock       domain.Clock
	defaultAud  string
	defaultTTL  time.Duration
}

// NewService 는 신규 Service 인스턴스를 생성한다.
func NewService(keyMgr keys.KeyManager, clients ClientRegistry, auditWriter audit.Writer, clock domain.Clock) *Service {
	if clock == nil {
		clock = domain.RealClock{}
	}
	if clients == nil {
		clients = NewInMemoryClientRegistry()
	}
	return &Service{
		keyMgr:      keyMgr,
		clients:     clients,
		auditWriter: auditWriter,
		clock:       clock,
		defaultAud:  "authz-service",
		defaultTTL:  1 * time.Hour,
	}
}

// IssueToken 은 클라이언트 인증 후 RFC 9068 Bearer Access Token을 생성하고 Zone A Ed25519 개인키로 서명한다.
func (s *Service) IssueToken(req IssueRequest, opts IssueOptions, auditCtx domain.AuditContext) (*IssueResult, error) {
	// 1. 클라이언트 인증
	clientInfo, err := s.clients.AuthenticateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		if s.auditWriter != nil {
			var reason domain.Reason = domain.ReasonInvalidToken
			switch {
			case errors.Is(err, ErrUnknownClient):
				reason = domain.ReasonAuthnUnknownClient
			case errors.Is(err, ErrInvalidSecret):
				reason = domain.ReasonAuthnInvalidSecret
			case errors.Is(err, ErrClientSuspended):
				reason = domain.ReasonAuthnClientSuspended
			}
			traceID := auditCtx.TraceID
			if traceID == "" {
				traceID = fmt.Sprintf("trace-%d", s.clock.Now().UnixNano())
			}
			actor := auditCtx.Actor
			if actor == "" {
				actor = req.ClientID
			}
			_ = s.auditWriter.Log(audit.Event{
				Timestamp: s.clock.Now().UTC(),
				TraceID:   traceID,
				Step:      "020-issue-authn",
				Actor:     actor,
				Action:    "token.issue.deny",
				Decision:  "deny",
				Reason:    string(reason),
				Success:   false,
				Metadata: map[string]interface{}{
					"client_id": req.ClientID,
					"error":     err.Error(),
					"reason":    string(reason),
				},
			})
		}
		return nil, fmt.Errorf("client authentication failed: %w", err)
	}

	// 2. Subject 위임 권한 검사
	if strings.TrimSpace(req.Subject) == "" {
		return nil, errors.New("subject is required")
	}
	if !clientInfo.IsSubjectAllowed(req.Subject) {
		return nil, fmt.Errorf("client %s is not authorized to request tokens for subject %s (%s)",
			req.ClientID, req.Subject, domain.ReasonNoActiveGrant)
	}

	// 3. 서명 키(Zone A Active Key) 획득
	signingKey, err := s.keyMgr.GetActiveSigningKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get active signing key: %w", err)
	}

	// 4. 클레임 구성
	now := s.clock.Now().UTC()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	aud := req.Audience
	if strings.TrimSpace(aud) == "" {
		aud = s.defaultAud
	}
	epoch := req.Epoch
	if epoch < 1 {
		epoch = 1
	}

	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("failed to generate jti: %w", err)
	}

	claims := domain.TokenClaims{
		Issuer:          "authz-harness",
		Subject:         req.Subject,
		Audience:        aud,
		ClientID:        req.ClientID,
		ExpiresAt:       now.Add(ttl).Unix(),
		IssuedAt:        now.Unix(),
		NotBefore:       now.Unix(),
		JWTID:           jti,
		Scope:           req.Scope,
		Epoch:           epoch,
		Actor:           req.Actor,
		DelegationDepth: req.DelegationDepth,
	}

	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("invalid token claims: %w", err)
	}

	// 5. 헤더 구성
	header := JWTHeader{
		Type:      "at+jwt", // RFC 9068 표준
		Algorithm: "EdDSA",
		KeyID:     signingKey.KID,
	}

	// 결함 주입 (Fault Injection)
	if opts.TamperTyp != "" {
		header.Type = opts.TamperTyp
	}
	if opts.TamperAlgNone {
		header.Algorithm = "none"
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	var signatureB64 string
	if opts.TamperAlgNone {
		// alg: none 공격 시 서명 부분을 비움
		signatureB64 = ""
	} else {
		sig := ed25519.Sign(signingKey.PrivateKey, []byte(signingInput))
		if opts.TamperSignature && len(sig) > 0 {
			// 서명 마지막 바이트 반전 (위조 서명)
			sig[len(sig)-1] ^= 0xFF
		}
		signatureB64 = base64.RawURLEncoding.EncodeToString(sig)
	}

	tokenString := signingInput + "." + signatureB64

	// 6. Zero Leakage 감사 이벤트 기록: 원시 토큰 배제, jti 및 메타데이터만 기록
	if s.auditWriter != nil {
		traceID := auditCtx.TraceID
		if traceID == "" {
			traceID = fmt.Sprintf("trace-%d", now.UnixNano())
		}
		actor := auditCtx.Actor
		if actor == "" {
			actor = req.ClientID
		}

		auditEv := audit.Event{
			Timestamp: now,
			TraceID:   traceID,
			Step:      "020-issue",
			Actor:     actor,
			Action:    "token.issued",
			Success:   true,
			Metadata: map[string]interface{}{
				"token_jti":   claims.JWTID,
				"token_kid":   header.KeyID,
				"token_typ":   header.Type,
				"token_alg":   header.Algorithm,
				"client_id":   claims.ClientID,
				"subject":     claims.Subject,
				"audience":    claims.Audience,
				"scope":       claims.Scope,
				"expires_at":  claims.ExpiresAt,
				"epoch":       int64(claims.Epoch),
				"tampered":    opts.TamperSignature || opts.TamperAlgNone || opts.TamperTyp != "",
			},
		}
		if err := s.auditWriter.Log(auditEv); err != nil {
			return nil, fmt.Errorf("failed to write audit event: %w", err)
		}
	}

	return &IssueResult{
		TokenString: tokenString,
		Claims:      claims,
		KeyID:       header.KeyID,
	}, nil
}

func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
