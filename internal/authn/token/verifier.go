package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/domain"
)

var (
	// ErrTokenMalformed 는 JWT 구조 또는 인코딩 결함이다.
	ErrTokenMalformed = errors.New("malformed token structure")

	// ErrInvalidType 은 RFC 9068 typ 헤더 불일치다.
	ErrInvalidType = errors.New("invalid token typ (expected at+jwt)")

	// ErrAlgNotAllowed 는 허용되지 않은 서명 알고리즘이다.
	ErrAlgNotAllowed = errors.New("token algorithm not allowed")

	// ErrInvalidSignature 는 Ed25519 디지털 서명 검증 실패다.
	ErrInvalidSignature = errors.New("invalid digital signature")

	// ErrTokenExpired 는 토큰 유효기간 경과다.
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenNotYetValid 는 토큰 nbf 미도달이다.
	ErrTokenNotYetValid = errors.New("token is not yet valid")

	// ErrInvalidIssAud 는 발급자 또는 수신자 불일치다.
	ErrInvalidIssAud = errors.New("invalid token issuer or audience")

	// ErrSubjectMismatch 는 기대된 주체 불일치다.
	ErrSubjectMismatch = errors.New("token subject mismatch")
)

// VerifyOptions 는 토큰 검증 시 검사할 옵션들이다.
type VerifyOptions struct {
	ExpectedAudience string
	ExpectedSubject  string
	RecordReplay     bool // true 인 경우 jti 를 Replay 원장에 검사 및 소비 등록
	ClockOffset      time.Duration
}

// TokenVerifier 인터페이스다.
type TokenVerifier interface {
	VerifyToken(tokenStr string, opts VerifyOptions, auditCtx domain.AuditContext) (*domain.VerifiedClaims, error)
	InspectToken(tokenStr string) (*JWTHeader, *domain.TokenClaims, error)
}

// Verifier 는 RFC 8725 BCP 및 Gate 1 검증을 수행하는 구현체다.
type Verifier struct {
	keyMgr       keys.KeyManager
	replayLedger ReplayLedger
	auditWriter  audit.Writer
	clock        domain.Clock
	expectedIss  string
}

// NewVerifier 는 Gate 1 Verifier 를 생성한다.
func NewVerifier(keyMgr keys.KeyManager, replayLedger ReplayLedger, auditWriter audit.Writer, clock domain.Clock) *Verifier {
	if clock == nil {
		clock = domain.RealClock{}
	}
	return &Verifier{
		keyMgr:       keyMgr,
		replayLedger: replayLedger,
		auditWriter:  auditWriter,
		clock:        clock,
		expectedIss:  domain.DefaultIssuer,
	}
}

// InspectToken 은 서명 검증 없이 Header 와 Claims 를 파싱하여 JSON 구조체로 반환한다.
func (v *Verifier) InspectToken(tokenStr string) (*JWTHeader, *domain.TokenClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, "inspect", fmt.Sprintf("expected 3 dot-separated parts, got %d", len(parts)), ErrTokenMalformed)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, "inspect", fmt.Sprintf("failed to decode header base64: %v", err), ErrTokenMalformed)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, "inspect", fmt.Sprintf("failed to decode claims base64: %v", err), ErrTokenMalformed)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, "inspect", fmt.Sprintf("failed to parse header json: %v", err), ErrTokenMalformed)
	}

	var claims domain.TokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, "inspect", fmt.Sprintf("failed to parse claims json: %v", err), ErrTokenMalformed)
	}

	return &header, &claims, nil
}

// VerifyToken 은 9단계 엄격한 Gate 1 검증 파이프라인을 실행한다.
func (v *Verifier) VerifyToken(tokenStr string, opts VerifyOptions, auditCtx domain.AuditContext) (*domain.VerifiedClaims, error) {
	effectiveClock := v.clock
	if opts.ClockOffset != 0 {
		effectiveClock = domain.NewOffsetClock(v.clock, opts.ClockOffset)
	}
	now := effectiveClock.Now().UTC()

	// 1단계: 3단 점 분리 형식 검증
	if strings.TrimSpace(tokenStr) == "" {
		v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "token is missing or empty")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", "token is missing or empty", ErrTokenMalformed)
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "token format error")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("must contain 3 parts, got %d", len(parts)), ErrTokenMalformed)
	}

	headerB64, claimsB64, sigB64 := parts[0], parts[1], parts[2]
	signingInput := headerB64 + "." + claimsB64

	// 2단계: 헤더 디코딩 및 typ 검증 (RFC 9068: at+jwt)
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "header base64 decode fail")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("header b64 decode: %v", err), ErrTokenMalformed)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "header json unmarshal fail")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("header json unmarshal: %v", err), ErrTokenMalformed)
	}

	if strings.ToLower(header.Type) != "at+jwt" {
		v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenInvalidType, fmt.Sprintf("invalid typ: %s", header.Type))
		return nil, domain.NewError(domain.ReasonTokenInvalidType, "gate1", fmt.Sprintf("got %s", header.Type), ErrInvalidType)
	}

	// 3단계: 알고리즘 화이트리스트 대조 (alg: EdDSA)
	if header.Algorithm != "EdDSA" {
		v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenAlgNotAllowed, fmt.Sprintf("disallowed alg: %s", header.Algorithm))
		return nil, domain.NewError(domain.ReasonTokenAlgNotAllowed, "gate1", fmt.Sprintf("alg %s is rejected", header.Algorithm), ErrAlgNotAllowed)
	}

	// 4단계: 키 조회 및 상태 확인 (Zone B JWKS)
	jwk, err := v.keyMgr.GetVerificationKey(header.KeyID)
	if err != nil {
		reason := domain.ReasonTokenKeyNotFound
		if errors.Is(err, keys.ErrKeyRetired) {
			reason = domain.ReasonTokenKeyRetired
		}
		v.logAudit(now, auditCtx, "", header.KeyID, false, reason, err.Error())
		return nil, domain.NewError(reason, "gate1", "verification key check failed", err)
	}

	// 5단계: 암호학적 디지털 서명 검증
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(jwk.PublicKey)
	if err != nil {
		v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "jwk pubkey b64 decode fail")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("failed to decode jwk pubkey: %v", err), ErrTokenMalformed)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "sig b64 decode fail")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("sig b64 decode: %v", err), ErrTokenMalformed)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(signingInput), sigBytes) {
		v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenInvalidSignature, "signature mismatch")
		return nil, domain.NewError(domain.ReasonTokenInvalidSignature, "gate1", "signature mismatch", ErrInvalidSignature)
	}

	// 6단계: 클레임 디코딩 및 필수값 검증
	claimsBytes, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "claims b64 decode fail")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("claims b64 decode: %v", err), ErrTokenMalformed)
	}

	var claims domain.TokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "claims json unmarshal fail")
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("claims json unmarshal: %v", err), ErrTokenMalformed)
	}

	if err := claims.Validate(); err != nil {
		v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenMalformed, err.Error())
		return nil, domain.NewError(domain.ReasonTokenMalformed, "gate1", fmt.Sprintf("validation fail: %v", err), ErrTokenMalformed)
	}

	// 7단계: 주체 및 수신자 대조
	if claims.Issuer != v.expectedIss {
		v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenInvalidIssAud, "issuer mismatch")
		return nil, domain.NewError(domain.ReasonTokenInvalidIssAud, "gate1", fmt.Sprintf("expected iss %s, got %s", v.expectedIss, claims.Issuer), ErrInvalidIssAud)
	}

	if opts.ExpectedAudience != "" && claims.Audience != opts.ExpectedAudience {
		v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenInvalidIssAud, "audience mismatch")
		return nil, domain.NewError(domain.ReasonTokenInvalidIssAud, "gate1", fmt.Sprintf("expected aud %s, got %s", opts.ExpectedAudience, claims.Audience), ErrInvalidIssAud)
	}

	if opts.ExpectedSubject != "" && claims.Subject != opts.ExpectedSubject {
		v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenSubjectMismatch, "subject mismatch")
		return nil, domain.NewError(domain.ReasonTokenSubjectMismatch, "gate1", fmt.Sprintf("expected sub %s, got %s", opts.ExpectedSubject, claims.Subject), ErrSubjectMismatch)
	}

	// 8단계: 시간 유효성 검증
	nowUnix := now.Unix()
	if claims.NotBefore > 0 && nowUnix < claims.NotBefore {
		v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenNotYetValid, "token not yet valid")
		return nil, domain.NewError(domain.ReasonTokenNotYetValid, "gate1", fmt.Sprintf("nbf %d > now %d", claims.NotBefore, nowUnix), ErrTokenNotYetValid)
	}

	if nowUnix >= claims.ExpiresAt {
		v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenExpired, "token expired")
		return nil, domain.NewError(domain.ReasonTokenExpired, "gate1", fmt.Sprintf("exp %d <= now %d", claims.ExpiresAt, nowUnix), ErrTokenExpired)
	}

	// 9단계: Replay 원장 소비 검사
	// 예산 토큰(Budget != nil)은 다회 호출 토큰이므로 1회성 소비를 건너뛰고 예산 원장이 횟수를 통제한다.
	if opts.RecordReplay && v.replayLedger != nil && claims.Budget == nil {
		expTime := time.Unix(claims.ExpiresAt, 0).UTC()
		if err := v.replayLedger.CheckAndConsume(claims.JWTID, expTime); err != nil {
			v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenReplayDetected, err.Error())
			return nil, domain.NewError(domain.ReasonTokenReplayDetected, "gate1", "token replay detected", err)
		}
	}

	// 검증 성공 감사 이벤트 기록
	v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, true, domain.ReasonAuthorized, "gate 1 verified successfully")

	return &domain.VerifiedClaims{
		Claims:     claims,
		KeyID:      header.KeyID,
		Algorithm:  header.Algorithm,
		VerifiedAt: now,
	}, nil
}

func (v *Verifier) logAudit(now time.Time, ctx domain.AuditContext, jti, kid string, success bool, reason domain.Reason, msg string) {
	if v.auditWriter == nil {
		return
	}
	traceID := ctx.TraceID
	if traceID == "" {
		traceID = fmt.Sprintf("trace-%d", now.UnixNano())
	}
	actor := ctx.Actor
	if actor == "" {
		actor = "token-verifier"
	}

	meta := map[string]interface{}{
		"gate":      "gate-1-token",
		"token_kid": kid,
		"reason":    string(reason),
		"message":   msg,
	}
	if jti != "" {
		meta["token_jti"] = jti
	}

	_ = v.auditWriter.Log(audit.Event{
		Timestamp: now,
		TraceID:   traceID,
		Step:      "020-verify",
		Actor:     actor,
		Action:    "authn.verify",
		Decision:  map[bool]string{true: "allow", false: "deny"}[success],
		Reason:    string(reason),
		TokenJTI:  jti,
		Success:   success,
		Metadata:  meta,
	})
}
