// Package token 은 RFC 9068 표준 OAuth 2.1 Bearer Access Token 발급, 검증, 리플레이 방지 및 클라이언트 인증 서비스를 제공한다.
//
// [토큰 발급 아키텍처 및 보안 원칙]
// 1. RFC 9068 JOSE 헤더 규약 강제:
//   - typ: "at+jwt" (액세스 토큰 명시, 혼동 공격 방어)
//   - alg: "EdDSA" (Ed25519 전자 서명)
//   - kid: 현재 활성 서명키의 고유 식별자
//
// 2. 비대칭 개인키 서명 (Zone A 전용):
//   - keys.KeyManager 를 통해 현재 활성(active) 상태인 Ed25519 개인키를 조회하여 서명한다.
//   - Zone B(VerifyOnly) 모드에서는 개인키가 없으므로 발급이 불가능하다 (Fail-Closed).
//
// 3. 결함 주입(Fault Injection) 지원 (IssueOptions):
//   - 보안 부정 테스트(Negative Testing)를 위해 서명 위조(TamperSignature), alg:none 변조(TamperAlgNone),
//     typ 헤더 변조(TamperTyp), 만료 시간 변조(TamperExpired)를 시뮬레이션할 수 있다.
//
// 4. Zero Leakage 감사 기록:
//   - 발급 완료 시 감사 로그(audit.jsonl)에는 서명된 토큰 원문 대신 jti 와 발급 메타데이터만 기록한다.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/domain"
)

// IssueRequest 는 RFC 9068 Access Token 발급을 위한 요청 매개변수 집합이다.
type IssueRequest struct {
	// ClientID 는 발급을 요청하는 OAuth 2.1 클라이언트 식별자다.
	ClientID string

	// ClientSecret 은 클라이언트 자격증명 비밀값이다.
	ClientSecret string

	// Subject 는 토큰이 부여될 대상 주체 식별자다 (예: "worker-01").
	Subject string

	// Scope 는 공백으로 구분된 인가 권한 문자열이다 (예: "file:read:tasks.txt file:write").
	Scope string

	// Audience 는 토큰의 수신 대상 리소스 서버 식별자다 (기본값: "authz-harness").
	Audience string

	// TTL 은 토큰의 유효 수명이다 (기본값: 1시간).
	TTL time.Duration

	// Epoch 는 발급 시점 주체의 보안 세대 번호다.
	Epoch domain.Epoch

	// Actor 는 위임된 토큰일 경우 선대 부모 주체들의 계보 사슬이다 (RFC 8693).
	Actor *domain.ActorClaim

	// DelegationDepth 는 위임 허용 잔여 깊이다.
	DelegationDepth int

	// Budget 은 호출·바이트 예산 상한이다. 위임 체인 없는 루트면 원장에 등록된다.
	Budget *domain.Budget
}

// IssueOptions 는 보안 가드레일 부정 테스트(Fault Injection)를 위한 토큰 변조 옵션이다.
type IssueOptions struct {
	// TamperSignature 가 true 면 서명 바이트의 마지막 바이트를 반전시켜 유효하지 않은 서명을 생성한다.
	TamperSignature bool

	// TamperAlgNone 이 true 면 alg 헤더를 "none" 으로 조작하고 서명부를 비운다.
	TamperAlgNone bool

	// TamperTyp 이 비어있지 않으면 typ 헤더를 해당 값으로 교체한다 (예: "JWT").
	TamperTyp string

	// TamperExpired 가 true 면 이미 만료된 과거 시간(exp/iat/nbf)으로 서명 발급한다.
	TamperExpired bool
}

// IssueResult 는 토큰 발급 성공 시 반환되는 결과 묶음이다.
type IssueResult struct {
	// TokenString 은 "헤더.페이로드.서명" 형태의 완전한 Base64URL JWT 문자열이다.
	TokenString string `json:"token"`

	// Claims 는 서명에 사용된 정규화된 클레임 구조체다.
	Claims domain.TokenClaims `json:"claims"`

	// KeyID 는 서명에 사용된 활성 키 식별자다 (kid).
	KeyID string `json:"kid"`
}

// TokenIssuer 인터페이스는 RFC 9068 Access Token 을 발급하는 추상 명세다.
type TokenIssuer interface {
	// IssueToken 은 주어진 요청과 옵션에 따라 토큰을 발급하고 감사 로그를 기록한다.
	IssueToken(req IssueRequest, opts IssueOptions, auditCtx domain.AuditContext) (*IssueResult, error)
}

// JWTHeader 는 JOSE Header 구조체다 (RFC 7515 / RFC 9068).
type JWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

// Service 는 RFC 9068 Bearer Access Token 의 발급, 서명, 감사 기록 및 예산 등록을 총괄하는 코어 서비스다.
type Service struct {
	keyMgr      keys.KeyManager
	clients     ClientRegistry
	auditWriter audit.Writer
	clock       domain.Clock
	defaultAud  string
	defaultTTL  time.Duration
	budgets     budget.Ledger
}

// ServiceOption 은 Service 의 선택적 의존성 주입을 위한 함수형 옵션(Functional Option)이다.
type ServiceOption func(*Service)

// WithBudgetLedger 는 예산 루트 토큰 등록에 쓸 예산 원장(budget.Ledger)을 주입한다.
func WithBudgetLedger(l budget.Ledger) ServiceOption {
	return func(s *Service) { s.budgets = l }
}

// NewService 는 신규 Service 인스턴스를 생성한다.
// DIP 원칙에 따라 시계(domain.Clock), 키 관리자(keys.KeyManager), 클라이언트 저장소(ClientRegistry),
// 감사 기록기(audit.Writer)를 외부에서 주입받는다.
func NewService(keyMgr keys.KeyManager, clients ClientRegistry, auditWriter audit.Writer, clock domain.Clock, opts ...ServiceOption) *Service {
	if clock == nil {
		clock = domain.RealClock{}
	}
	if clients == nil {
		clients = NewInMemoryClientRegistry()
	}
	s := &Service{
		keyMgr:      keyMgr,
		clients:     clients,
		auditWriter: auditWriter,
		clock:       clock,
		defaultAud:  domain.DefaultAudience,
		defaultTTL:  1 * time.Hour,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// IssueToken 은 클라이언트 인증 후 RFC 9068 Bearer Access Token을 생성하고 Zone A Ed25519 개인키로 서명한다.
// 실패는 이 입구에서 token.issue.deny 로 한 곳에서 기록한다 (성공 감사 실패는 다시 기록하지 않는다).
func (s *Service) IssueToken(req IssueRequest, opts IssueOptions, auditCtx domain.AuditContext) (*IssueResult, error) {
	res, authnStage, err := s.issueToken(req, opts, auditCtx)
	if err == nil {
		return res, nil
	}
	if s.auditWriter == nil || domain.ReasonFromError(err, "") == domain.ReasonAuditLogFailed {
		return nil, err
	}
	def, step := domain.ReasonInternalError, "token.issue"
	if authnStage {
		def, step = domain.ReasonInvalidToken, "token.issue_authn"
	}
	reason := domain.ReasonFromError(err, def)
	traceID := auditCtx.TraceID
	if traceID == "" {
		traceID = fmt.Sprintf("trace-%d", s.clock.Now().UnixNano())
	}
	actor := auditCtx.Actor
	if actor == "" {
		actor = req.ClientID
	}
	if aerr := s.auditWriter.Log(audit.Event{
		Timestamp: s.clock.Now().UTC(),
		TraceID:   traceID,
		Step:      step,
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
	}); aerr != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "failed to record issue deny audit log", aerr)
	}
	return nil, err
}

// issueToken 은 토큰 발급의 실질적 본문 로직이다.
// 두 번째 반환값 authnStage 는 실패 원인이 클라이언트 인증 단계(Step 1)에서 기인했는지를 식별한다.
func (s *Service) issueToken(req IssueRequest, opts IssueOptions, auditCtx domain.AuditContext) (*IssueResult, bool, error) {
	// 1. 클라이언트 자격증명 인증 (Client Registry 조회)
	clientInfo, err := s.clients.AuthenticateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, true, fmt.Errorf("client authentication failed: %w", err)
	}

	// 2. Subject 위임 권한 검사 (주체 요청 적격성 확인)
	if strings.TrimSpace(req.Subject) == "" {
		return nil, false, domain.NewError(domain.ReasonInvalidArguments, "subject is required", nil)
	}
	if !clientInfo.IsSubjectAllowed(req.Subject) {
		return nil, false, domain.NewError(domain.ReasonNoActiveGrant, fmt.Sprintf("client %s is not authorized to request tokens for subject %s", req.ClientID, req.Subject), nil)
	}

	// 3. 서명 키(Zone A Active Key) 획득
	signingKey, err := s.keyMgr.GetActiveSigningKey()
	if err != nil {
		return nil, false, domain.NewError(domain.ReasonInternalError, "failed to get active signing key", err)
	}

	// 4. 클레임 구성 (RFC 9068 및 시스템 기본값 적용)
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
		return nil, false, fmt.Errorf("failed to generate jti: %w", err)
	}

	claims := domain.TokenClaims{
		Issuer:          domain.DefaultIssuer,
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
	if req.Budget != nil {
		b := *req.Budget
		claims.Budget = &b
	}

	// 결함 주입: 만료된 토큰 생성 테스트 시뮬레이션
	if opts.TamperExpired {
		// 1시간 전 발급, 30분 전 만료
		claims.IssuedAt = now.Add(-1 * time.Hour).Unix()
		claims.NotBefore = claims.IssuedAt
		claims.ExpiresAt = now.Add(-30 * time.Minute).Unix()
	}

	// 클레임 정적 유효성 검증
	if err := claims.Validate(); err != nil {
		return nil, false, domain.NewError(domain.ReasonInvalidArguments, fmt.Sprintf("invalid token claims: %v", err), err)
	}

	// 4-1. 예산 루트(위임 체인 없음)는 원장 필수. 없으면 Fail-Closed 로 발급하지 않는다.
	registerBudget := claims.Budget != nil && claims.Actor == nil
	if registerBudget && s.budgets == nil {
		return nil, false, domain.NewError(domain.ReasonInternalError, "budget ledger is not configured for budget token issuance", nil)
	}

	// 5. JOSE 헤더 구성 (RFC 9068 규격 강제)
	header := JWTHeader{
		Type:      "at+jwt", // RFC 9068 표준
		Algorithm: "EdDSA",
		KeyID:     signingKey.KID,
	}

	// 결함 주입 (Fault Injection): 헤더 변조
	if opts.TamperTyp != "" {
		header.Type = opts.TamperTyp
	}
	if opts.TamperAlgNone {
		header.Algorithm = "none"
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	// Ed25519 전자 서명 생성
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

	// 5-1. 예산 루트 등록. 실패하면 토큰을 반환하지 않는다.
	if registerBudget {
		if err := s.budgets.Init(claims.JWTID, *claims.Budget, claims.ExpiresAt); err != nil {
			return nil, false, fmt.Errorf("failed to register budget ledger entry: %w", err)
		}
	}

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
			Step:      "token.issue",
			Actor:     actor,
			Action:    "token.issued",
			Success:   true,
			Metadata: map[string]interface{}{
				"token_jti":  claims.JWTID,
				"token_kid":  header.KeyID,
				"token_typ":  header.Type,
				"token_alg":  header.Algorithm,
				"client_id":  claims.ClientID,
				"subject":    claims.Subject,
				"audience":   claims.Audience,
				"scope":      claims.Scope,
				"expires_at": claims.ExpiresAt,
				"epoch":      int64(claims.Epoch),
				"tampered":   opts.TamperSignature || opts.TamperAlgNone || opts.TamperTyp != "" || opts.TamperExpired,
			},
		}
		if err := s.auditWriter.Log(auditEv); err != nil {
			return nil, false, domain.NewError(domain.ReasonAuditLogFailed, "failed to write audit event", err)
		}
	}

	return &IssueResult{
		TokenString: tokenString,
		Claims:      claims,
		KeyID:       header.KeyID,
	}, false, nil
}

// generateJTI 는 암호학적으로 안전한 16바이트(128비트) 난수 기반 JTI 문자열을 생성한다.
func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
