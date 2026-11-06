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
	CheckReplay      bool // true 인 경우 jti 가 이미 소비되었는지 읽기만 확인한다(소비는 ConsumeReplay)
	ClockOffset      time.Duration
}

// TokenVerifier 인터페이스다.
type TokenVerifier interface {
	VerifyToken(tokenStr string, opts VerifyOptions, auditCtx domain.AuditContext) (*domain.VerifiedClaims, error)
	InspectToken(tokenStr string) (*JWTHeader, *domain.TokenClaims, error)
	// ConsumeReplay 는 PDP allow 뒤에 jti 를 원자적으로 소비한다. 예산 토큰이거나 원장이 없으면 아무것도 하지 않는다.
	ConsumeReplay(claims domain.TokenClaims, auditCtx domain.AuditContext) error
}

// Verifier 는 RFC 8725 BCP 및 authn 단계 검증을 수행하는 구현체다.
type Verifier struct {
	keyMgr       keys.KeyManager
	replayLedger ReplayLedger
	auditWriter  audit.Writer
	clock        domain.Clock
	expectedIss  string
}

// NewVerifier 는 authn 단계 Verifier 를 생성한다.
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
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("expected 3 dot-separated parts, got %d", len(parts)), ErrTokenMalformed)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("failed to decode header base64: %v", err), ErrTokenMalformed)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("failed to decode claims base64: %v", err), ErrTokenMalformed)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("failed to parse header json: %v", err), ErrTokenMalformed)
	}

	var claims domain.TokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("failed to parse claims json: %v", err), ErrTokenMalformed)
	}

	return &header, &claims, nil
}

// VerifyToken 은 9단계 엄격한 authn 단계 검증 파이프라인을 실행한다.
func (v *Verifier) VerifyToken(tokenStr string, opts VerifyOptions, auditCtx domain.AuditContext) (*domain.VerifiedClaims, error) {
	effectiveClock := v.clock
	if opts.ClockOffset != 0 {
		effectiveClock = domain.NewOffsetClock(v.clock, opts.ClockOffset)
	}
	now := effectiveClock.Now().UTC()

	// 1단계: 3단 점 분리 형식 검증
	if strings.TrimSpace(tokenStr) == "" {
		if aerr := v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "token is missing or empty"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, "token is missing or empty", ErrTokenMalformed)
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		if aerr := v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "token format error"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("must contain 3 parts, got %d", len(parts)), ErrTokenMalformed)
	}

	headerB64, claimsB64, sigB64 := parts[0], parts[1], parts[2]
	signingInput := headerB64 + "." + claimsB64

	// 2단계: 헤더 디코딩 및 typ 검증 (RFC 9068: at+jwt)
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		if aerr := v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "header base64 decode fail"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("header b64 decode: %v", err), ErrTokenMalformed)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		if aerr := v.logAudit(now, auditCtx, "", "", false, domain.ReasonTokenMalformed, "header json unmarshal fail"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("header json unmarshal: %v", err), ErrTokenMalformed)
	}

	if strings.ToLower(header.Type) != "at+jwt" {
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenInvalidType, fmt.Sprintf("invalid typ: %s", header.Type)); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenInvalidType, fmt.Sprintf("got %s", header.Type), ErrInvalidType)
	}

	// 3단계: 알고리즘 화이트리스트 대조 (alg: EdDSA)
	if header.Algorithm != "EdDSA" {
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenAlgNotAllowed, fmt.Sprintf("disallowed alg: %s", header.Algorithm)); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenAlgNotAllowed, fmt.Sprintf("alg %s is rejected", header.Algorithm), ErrAlgNotAllowed)
	}

	// 4단계: 키 조회 및 상태 확인 (Zone B JWKS)
	jwk, err := v.keyMgr.GetVerificationKey(header.KeyID)
	if err != nil {
		reason := domain.ReasonTokenKeyNotFound
		if errors.Is(err, keys.ErrKeyRetired) {
			reason = domain.ReasonTokenKeyRetired
		}
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, reason, err.Error()); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(reason, "verification key check failed", err)
	}

	// 5단계: 암호학적 디지털 서명 검증
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(jwk.PublicKey)
	if err != nil {
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "jwk pubkey b64 decode fail"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("failed to decode jwk pubkey: %v", err), ErrTokenMalformed)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "sig b64 decode fail"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("sig b64 decode: %v", err), ErrTokenMalformed)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(signingInput), sigBytes) {
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenInvalidSignature, "signature mismatch"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenInvalidSignature, "signature mismatch", ErrInvalidSignature)
	}

	// 6단계: 클레임 디코딩 및 필수값 검증
	claimsBytes, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "claims b64 decode fail"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("claims b64 decode: %v", err), ErrTokenMalformed)
	}

	var claims domain.TokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		if aerr := v.logAudit(now, auditCtx, "", header.KeyID, false, domain.ReasonTokenMalformed, "claims json unmarshal fail"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("claims json unmarshal: %v", err), ErrTokenMalformed)
	}

	if err := claims.Validate(); err != nil {
		if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenMalformed, err.Error()); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenMalformed, fmt.Sprintf("validation fail: %v", err), ErrTokenMalformed)
	}

	// 7단계: 주체 및 수신자 대조
	if claims.Issuer != v.expectedIss {
		if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenInvalidIssAud, "issuer mismatch"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenInvalidIssAud, fmt.Sprintf("expected iss %s, got %s", v.expectedIss, claims.Issuer), ErrInvalidIssAud)
	}

	if opts.ExpectedAudience != "" && claims.Audience != opts.ExpectedAudience {
		if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenInvalidIssAud, "audience mismatch"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenInvalidIssAud, fmt.Sprintf("expected aud %s, got %s", opts.ExpectedAudience, claims.Audience), ErrInvalidIssAud)
	}

	if opts.ExpectedSubject != "" && claims.Subject != opts.ExpectedSubject {
		if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenSubjectMismatch, "subject mismatch"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenSubjectMismatch, fmt.Sprintf("expected sub %s, got %s", opts.ExpectedSubject, claims.Subject), ErrSubjectMismatch)
	}

	// 8단계: 시간 유효성 검증
	nowUnix := now.Unix()
	if claims.NotBefore > 0 && nowUnix < claims.NotBefore {
		if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenNotYetValid, "token not yet valid"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenNotYetValid, fmt.Sprintf("nbf %d > now %d", claims.NotBefore, nowUnix), ErrTokenNotYetValid)
	}

	if nowUnix >= claims.ExpiresAt {
		if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenExpired, "token expired"); aerr != nil {
			return nil, auditFailure(aerr)
		}
		return nil, domain.NewError(domain.ReasonTokenExpired, fmt.Sprintf("exp %d <= now %d", claims.ExpiresAt, nowUnix), ErrTokenExpired)
	}

	// 9단계: Replay 원장 소비 검사
	// 예산 토큰(Budget != nil)은 다회 호출 토큰이므로 1회성 소비를 건너뛰고 예산 원장이 횟수를 통제한다.
	if opts.RecordReplay && v.replayLedger != nil && claims.Budget == nil {
		expTime := time.Unix(claims.ExpiresAt, 0).UTC()
		if err := v.replayLedger.CheckAndConsume(claims.JWTID, expTime); err != nil {
			if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenReplayDetected, err.Error()); aerr != nil {
				return nil, auditFailure(aerr)
			}
			return nil, domain.NewError(domain.ReasonTokenReplayDetected, "token replay detected", err)
		}
	}

	// 9b단계: 읽기 전용 Replay 확인 (소비는 PDP allow 뒤 ConsumeReplay)
	if opts.CheckReplay && !opts.RecordReplay && v.replayLedger != nil && claims.Budget == nil {
		consumed, cerr := v.replayLedger.IsConsumed(claims.JWTID)
		if cerr != nil {
			return nil, domain.NewError(domain.ReasonInternalError, "replay ledger read failed", cerr)
		}
		if consumed {
			rerr := fmt.Errorf("%w: %s (%s)", ErrReplayDetected, claims.JWTID, domain.ReasonTokenReplayDetected)
			if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, false, domain.ReasonTokenReplayDetected, rerr.Error()); aerr != nil {
				return nil, auditFailure(aerr)
			}
			return nil, domain.NewError(domain.ReasonTokenReplayDetected, "token replay detected", rerr)
		}
	}

	// 검증 성공 감사 이벤트 기록
	if aerr := v.logAudit(now, auditCtx, claims.JWTID, header.KeyID, true, domain.ReasonAuthorized, "gate 1 verified successfully"); aerr != nil {
		return nil, auditFailure(aerr)
	}

	return &domain.VerifiedClaims{
		Claims:     claims,
		KeyID:      header.KeyID,
		Algorithm:  header.Algorithm,
		VerifiedAt: now,
	}, nil
}

func (v *Verifier) logAudit(now time.Time, ctx domain.AuditContext, jti, kid string, success bool, reason domain.Reason, msg string) error {
	if v.auditWriter == nil {
		return nil
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

	return v.auditWriter.Log(audit.Event{
		Timestamp: now,
		TraceID:   traceID,
		Step:      "token.verify",
		Actor:     actor,
		Action:    "authn.verified",
		Decision:  map[bool]string{true: "allow", false: "deny"}[success],
		Reason:    string(reason),
		TokenJTI:  jti,
		Success:   success,
		Metadata:  meta,
	})
}

// auditFailure 는 감사 기록 실패를 Fail-Closed 오류로 변환한다. 감사 없이 검증을 끝내지 않는다.
func auditFailure(err error) error {
	return domain.NewError(domain.ReasonAuditLogFailed, "audit log write failed", err)
}

// ConsumeReplay 는 PDP allow 직후 jti 를 CheckAndConsume 한 번으로 소비한다.
// 경합에서 지면 9단계와 같은 감사(TOKEN_REPLAY_DETECTED)를 남기고 11 을 반환한다.
func (v *Verifier) ConsumeReplay(claims domain.TokenClaims, auditCtx domain.AuditContext) error {
	if claims.Budget != nil || v.replayLedger == nil {
		return nil
	}
	now := v.clock.Now().UTC()
	expTime := time.Unix(claims.ExpiresAt, 0).UTC()
	if err := v.replayLedger.CheckAndConsume(claims.JWTID, expTime); err != nil {
		if aerr := v.logAudit(now, auditCtx, claims.JWTID, "", false, domain.ReasonTokenReplayDetected, err.Error()); aerr != nil {
			return auditFailure(aerr)
		}
		return domain.NewError(domain.ReasonTokenReplayDetected, "token replay detected", err)
	}
	return nil
}
