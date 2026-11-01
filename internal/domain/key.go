package domain

import (
	"crypto/ed25519"
	"time"
)

// KeyStatus 는 RFC 7517 기반 키 수명주기 상태다.
type KeyStatus string

const (
	// KeyStatusActive 는 서명 및 검증 모두에 사용 가능한 현재 기본 키다.
	KeyStatusActive KeyStatus = "active"

	// KeyStatusVerifyOnly 는 키 회전 후 신규 서명에는 사용되지 않고 기존 발급 토큰 검증에만 허용되는 상태다.
	KeyStatusVerifyOnly KeyStatus = "verify-only"

	// KeyStatusRetired 는 키 폐기(Revocation)되어 서명 및 검증 모두 거부되는 즉시 무효화 상태다.
	KeyStatusRetired KeyStatus = "retired"
)

// JWK 는 RFC 7517 규격의 JSON Web Key 구조체다 (Zone B jwks.pub.json 공개용).
// Zero Leakage 원칙에 따라 비밀키 필드(d 또는 seed)는 일절 포함하지 않는다.
type JWK struct {
	KID       string     `json:"kid"`
	KType     string     `json:"kty"` // OKP
	Curve     string     `json:"crv"` // Ed25519
	Algorithm string     `json:"alg"` // EdDSA
	Use       string     `json:"use"` // sig
	Status    KeyStatus  `json:"status"`
	PublicKey string     `json:"x"` // Base64URL 인코딩된 공개키
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

// JWKS 는 RFC 7517 규격의 JSON Web Key Set 구조체다.
type JWKS struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Keys      []JWK     `json:"keys"`
}

// SigningKey 는 Zone A에만 저장되고 토큰 서명에 사용되는 내부 키 구조체다.
type SigningKey struct {
	KID        string             `json:"kid"`
	Algorithm  string             `json:"alg"`
	Status     KeyStatus          `json:"status"`
	PrivateKey ed25519.PrivateKey `json:"-"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	CreatedAt  time.Time          `json:"created_at"`
}

// AuditContext 는 키 조작 또는 보안 이벤트 발생 시 감사 로그에 주입할 컨텍스트다.
type AuditContext struct {
	TraceID string
	Actor   string
	Reason  string
}
