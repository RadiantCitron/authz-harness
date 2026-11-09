// Package domain 은 RFC 7517 JSON Web Key(JWK) 및 암호화 키 수명주기 모델을 정의한다.
//
// [암호학적 키 수명주기와 Zero Leakage 원칙]
// 1. 비대칭 암호 알고리즘:
//    - 본 시스템은 Ed25519 (EdDSA) 고속 타원곡선 전자서명 알고리즘을 표준으로 채택한다.
// 2. Zone A 와 Zone B 의 데이터 모델 분리:
//    - SigningKey (Zone A 전용): 개인키(ed25519.PrivateKey)를 보유하며 json:"-" 태그로 직렬화 유출을 원천 방어한다.
//    - JWK (Zone B 공개용): Base64URL 인코딩된 공개키(x 필드)만을 포함하며, 비밀 시드나 개인키 필드는 모델 수준에서 존재하지 않는다.
// 3. RFC 7517 기반 3단계 수명주기 전이 (KeyStatus):
//    - active (서명/검증 가능) ➔ [회전(RotateKey)] ➔ verify-only (신규 서명 불가, 기존 토큰 검증만 허용)
//      ➔ [폐기(RevokeKey)] ➔ retired (서명/검증 모두 즉시 차단, Fail-Closed)
//
// [처리처 상호 참조 (Cross-Referencing)]
// - 키 관리자: internal/authn/keys/manager.go (NewManager, RotateKey, RevokeKey)
// - 키 저장소: internal/authn/keys/store.go (NewFileStore - 0700 권한 격리)
// - 단일 조립소: internal/app/builder.go (BuildStack 에서 Zone A/B 경로 바인딩)
package domain

import (
	"crypto/ed25519"
	"time"
)

// KeyStatus 는 RFC 7517 에 기반한 암호화 키의 현재 수명주기 상태다.
type KeyStatus string

const (
	// KeyStatusActive 는 토큰 서명(Signing)과 검증(Verification) 모두에 사용 가능한 현재 기본 활성 키 상태다.
	// 키 링(Key Ring) 내에서 오직 하나의 키만 active 상태를 유지한다.
	KeyStatusActive KeyStatus = "active"

	// KeyStatusVerifyOnly 는 키 회전(Rotate) 후 신규 서명에는 사용되지 않고,
	// 이미 발급된 유효 토큰의 서명 검증에만 허용되는 전환기 상태다.
	KeyStatusVerifyOnly KeyStatus = "verify-only"

	// KeyStatusRetired 는 키가 명시적으로 폐기(Revocation)되어 서명 및 검증이 모두 거부되는 무효화 상태다.
	// retired 키로 서명된 토큰이 인가 관문(PEP)에 인입되면 ReasonTokenKeyRetired 로 즉시 거부된다.
	KeyStatusRetired KeyStatus = "retired"
)

// JWK 는 RFC 7517 규격의 JSON Web Key 공개 메타데이터 구조체다 (Zone B jwks.pub.json 공개용).
//
// [Zero Leakage 보안 보장]
// 비밀키 필드(d 또는 seed)를 구조체 정의에서 원천 배제하여, JSON 직렬화 시 공개키 이외의
// 민감 비밀값이 네트워크나 비인가 영역으로 유출될 가능성을 컴파일 타임에 차단한다.
type JWK struct {
	// KID 는 키의 고유 식별자(Key ID)다. JWT 헤더의 kid 와 매핑된다.
	KID string `json:"kid"`

	// KType 은 키 유형이다 (Ed25519 의 경우 "OKP" - Octet Key Pair).
	KType string `json:"kty"`

	// Curve 는 타원곡선 파라미터다 (Ed25519 의 경우 "Ed25519").
	Curve string `json:"crv"`

	// Algorithm 은 서명 알고리즘이다 (EdDSA).
	Algorithm string `json:"alg"`

	// Use 는 키의 용도다 ("sig" - 디지털 서명용).
	Use string `json:"use"`

	// Status 는 키의 수명주기 상태다 (active, verify-only, retired).
	Status KeyStatus `json:"status"`

	// PublicKey 는 Base64URL(패딩 없음)로 인코딩된 32바이트 Ed25519 공개키 문자열이다 (RFC 8037 x 파라미터).
	PublicKey string `json:"x"`

	// CreatedAt 은 키가 최초 생성된 시각이다.
	CreatedAt time.Time `json:"created_at"`

	// RotatedAt 은 키가 active 에서 verify-only 로 회전된 시각이다 (회전되지 않았으면 nil).
	RotatedAt *time.Time `json:"rotated_at,omitempty"`

	// RetiredAt 은 키가 retired 상태로 폐기된 시각이다 (폐기되지 않았으면 nil).
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}

// JWKS 는 RFC 7517 규격의 JSON Web Key Set 구조체다.
// 여러 세대의 공개키 목록을 JSON 배열 형태로 캡슐화하여 클라이언트와 PEP 에 배포된다.
type JWKS struct {
	// Version 은 JWKS 스키마 버전이다.
	Version int `json:"version"`

	// UpdatedAt 은 키 링이 마지막으로 갱신(회전/폐기)된 시각이다.
	UpdatedAt time.Time `json:"updated_at"`

	// Keys 는 등록된 공개키 목록이다.
	Keys []JWK `json:"keys"`
}

// SigningKey 는 Zone A(개인키 저장소)에만 안전하게 보관되고 토큰 서명에 사용되는 내부 암호화 구조체다.
//
// [Zero Leakage 방어]
// PrivateKey 와 PublicKey 필드에 `json:"-"` 태그를 적용하여, 어떠한 경우에도 JSON 마샬링을 통해
// 원시 바이트가 외부에 노출되지 않도록 강제한다.
type SigningKey struct {
	// KID 는 키 식별자다.
	KID string `json:"kid"`

	// Algorithm 은 서명 알고리즘이다 (EdDSA).
	Algorithm string `json:"alg"`

	// Status 는 키 상태다.
	Status KeyStatus `json:"status"`

	// PrivateKey 는 Ed25519 64바이트 개인키 원본이다 (JSON 직렬화 제외).
	PrivateKey ed25519.PrivateKey `json:"-"`

	// PublicKey 는 Ed25519 32바이트 공개키 원본이다 (JSON 직렬화 제외).
	PublicKey ed25519.PublicKey `json:"-"`

	// CreatedAt 은 키 생성 시각이다.
	CreatedAt time.Time `json:"created_at"`
}

// AuditContext 는 키 생성, 회전, 폐기 등 민감 암호학적 조작 발생 시 감사 로그(audit.jsonl)에 주입할 컨텍스트다.
type AuditContext struct {
	TraceID string
	Actor   string
	Reason  string
}
