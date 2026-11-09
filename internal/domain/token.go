// Package domain 은 RFC 9068 표준 OAuth 2.1 Access Token 및 RFC 8693 Token Exchange 위임 클레임 모델을 정의한다.
//
// [토큰 아키텍처 및 보안 원칙]
// 1. RFC 9068 프로파일 준수:
//    - 발급자(iss), 수신처(aud), 주체(sub), 클라이언트(client_id), 만료(exp), 발급(iat), 개시(nbf), 고유ID(jti), 스코프(scope).
// 2. 시간 추상화와 결정론적 테스트 (DIP Clock):
//    - 코어 패키지 내 직접 time.Now() 호출을 금지하는 아키텍처 가드레일(TestArchitectureGuardrails/TC-130-01)을 만족하기 위해
//      모든 시간 검증은 domain.Clock 인터페이스를 통해 주입된다.
// 3. RFC 8693 위임 계보(Actor)와 연쇄 회수(Cascading Revocation):
//    - ActorClaim 은 부모-자식 위임 고리를 중첩(act.act...) 형태로 보관하며,
//      각 고리마다 위임 당시의 Epoch 를 각인하여 선대 조상의 권한 회수 시 자식 토큰도 연쇄 무효화한다.
//
// [조립 및 처리처 크로스체킹 (Cross-Referencing)]
// - 토큰 발급기: internal/authn/token/issuer.go (NewService 에서 Claims 조립 및 Ed25519 서명)
// - 토큰 검증기: internal/authn/token/verifier.go (VerifyToken 에서 서명, nbf, exp, aud 검증)
// - 토큰 교환기: internal/authn/exchange/service.go (Downscoping 시 ActorClaim 중첩 생성)
package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Clock 은 시스템 시간 조회를 추상화하는 DIP 포트 인터페이스다.
// 프로덕션 코드와 단위 테스트 간의 결합도를 끊어내며, 시간 경과에 따른 토큰 만료(exp)나
// 유효 개시(nbf) 시점 도래를 결정론적으로 시뮬레이션할 수 있게 한다.
type Clock interface {
	Now() time.Time
}

// RealClock 은 OS 시스템 현재 시각(UTC)을 반환하는 표준 Clock 구현체다.
// 프로덕션 런타임에서 기본값으로 주입된다.
type RealClock struct{}

// Now 는 시스템 현재 시각을 UTC 로 정규화하여 반환한다.
func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

// OffsetClock 은 기준 Clock 에 특정 오프셋(Duration)을 가감하여 시계를 가상 조작하는 Clock 구현체다.
// 시간 경과 테스트(예: 1시간 뒤로 시계를 돌려 토큰 만료 유도) 시 안전하게 사용된다.
type OffsetClock struct {
	Base   Clock
	Offset time.Duration
}

// NewOffsetClock 은 base 클럭과 offset 기간을 받아 OffsetClock 을 생성한다.
// base 가 nil 이면 RealClock{} 을 기본값으로 감싼다.
func NewOffsetClock(base Clock, offset time.Duration) *OffsetClock {
	if base == nil {
		base = RealClock{}
	}
	return &OffsetClock{
		Base:   base,
		Offset: offset,
	}
}

// Now 는 기준 시각에 오프셋을 더한 가상 시각을 반환한다.
func (c *OffsetClock) Now() time.Time {
	return c.Base.Now().Add(c.Offset)
}

// ActorClaim 은 RFC 8693 OAuth 2.0 Token Exchange §4.1 에 따른 위임 주체(Actor) 계보 클레임이다.
//
// [재귀적 중첩(Recursive Nesting) 구조]
// 부모 A 가 자식 B 에게 위임하고, B 가 다시 C 에게 위임하면:
// C 토큰의 sub="C", act.sub="B", act.act.sub="A" 와 같이 위임의 뿌리까지 계보가 보존된다.
//
// [보안 세대(Epoch) 연쇄 회수 원리]
// 각 고리마다 위임 발생 시점의 Epoch 가 기록된다.
// 주체 Snapshot 대조 시 조상 중 어느 하나라도 현재 Epoch 가 증가했으면(탈취/퇴사 등)
// 자식 토큰도 ReasonSubjectEpochRevoked 로 즉시 무효화된다.
type ActorClaim struct {
	Subject string      `json:"sub"`
	JWTID   string      `json:"jti,omitempty"`
	Epoch   Epoch       `json:"epoch,omitempty"` // 위임 시점 이 고리 주체의 Epoch (계보 연쇄 회수용)
	Actor   *ActorClaim `json:"act,omitempty"`
}

// TokenClaims 는 RFC 9068 표준 Bearer Access Token 클레임 세트다.
// Ed25519 개인키로 전자 서명되어 JSON Web Token (JWT) 형태로 인코딩된다.
type TokenClaims struct {
	// Issuer 는 토큰 발급 주체 식별자다 (예: "authz-harness").
	Issuer string `json:"iss"`

	// Subject 는 토큰이 부여된 대상 주체 식별자다 (예: "worker-01").
	Subject string `json:"sub"`

	// Audience 는 토큰을 수신하여 인가할 대상 리소스 서버 식별자다 (예: "authz-harness").
	Audience string `json:"aud"`

	// ClientID 는 토큰 발급을 요청한 OAuth 2.1 클라이언트 식별자다.
	ClientID string `json:"client_id"`

	// ExpiresAt 은 토큰 만료 Unix 타임스탬프(초)다 (exp).
	ExpiresAt int64 `json:"exp"`

	// IssuedAt 은 토큰 발급 Unix 타임스탬프(초)다 (iat).
	IssuedAt int64 `json:"iat"`

	// NotBefore 는 토큰 사용이 허용되는 시작 Unix 타임스탬프(초)다 (nbf).
	NotBefore int64 `json:"nbf"`

	// JWTID 는 토큰의 전역 고유 식별자다 (jti).
	// 리플레이 방지 장부(token.ReplayLedger)에 등록되어 1회성 소비 또는 중복 소비 방지의 기준이 된다.
	JWTID string `json:"jti"`

	// Scope 는 공백으로 구분된 인가 권한 문자열이다 (예: "file:read:tasks.txt file:write").
	Scope string `json:"scope"`

	// Epoch 는 발급 시점 주체의 보안 세대 번호다.
	Epoch Epoch `json:"epoch"`

	// Actor 는 위임된 토큰일 경우 선대 부모 주체들의 계보 사슬이다 (RFC 8693).
	Actor *ActorClaim `json:"act,omitempty"`

	// DelegationDepth 는 위임 허용 잔여 깊이다.
	DelegationDepth int `json:"delegation_depth,omitempty"`

	// Budget 은 토큰에 할당된 가용 소비 상한(호출 횟수, 읽기/쓰기 바이트)이다.
	Budget *Budget `json:"budget,omitempty"`
}

// Validate 는 발급 또는 검증 시 필수 클레임의 존재 여부와 시간 불변식을 엄격히 검증한다.
//
// [불변식 검증 항목]
// 1. 필수 식별자(iss, sub, aud, client_id, jti)의 공백 누락 검사
// 2. 시간 무결성: exp > 0, iat > 0, 그리고 반드시 exp > iat 성립
// 3. Epoch 유효성: epoch >= 1 (1-기반 세대 번호 준수)
// 4. 예산 유효성: budget 이 존재할 경우 MaxCalls > 0 등 세부 검증
func (c *TokenClaims) Validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("iss is required")
	}
	if strings.TrimSpace(c.Subject) == "" {
		return errors.New("sub is required")
	}
	if strings.TrimSpace(c.Audience) == "" {
		return errors.New("aud is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("client_id is required")
	}
	if strings.TrimSpace(c.JWTID) == "" {
		return errors.New("jti is required")
	}
	if c.ExpiresAt <= 0 {
		return errors.New("exp must be positive unix timestamp")
	}
	if c.IssuedAt <= 0 {
		return errors.New("iat must be positive unix timestamp")
	}
	if c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("exp (%d) must be greater than iat (%d)", c.ExpiresAt, c.IssuedAt)
	}
	if c.Epoch < 1 {
		return fmt.Errorf("epoch must be >= 1, got %d", c.Epoch)
	}
	if c.Budget != nil {
		if err := c.Budget.Validate(); err != nil {
			return fmt.Errorf("budget claim: %w", err)
		}
	}
	return nil
}

// VerifiedClaims 는 authn 단계 암호학적 서명 및 클레임 검증을 통과한 신뢰 토큰 정보다.
type VerifiedClaims struct {
	Claims     TokenClaims `json:"claims"`
	KeyID      string      `json:"kid"`
	Algorithm  string      `json:"alg"`
	VerifiedAt time.Time   `json:"verified_at"`
}
