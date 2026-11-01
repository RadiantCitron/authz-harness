package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Clock 은 시간 주입 및 가상 시계 지원 인터페이스다.
type Clock interface {
	Now() time.Time
}

// RealClock 은 시스템 현재 시각(UTC)을 반환하는 표준 Clock 구현체다.
type RealClock struct{}

// Now 는 시스템 UTC 시각을 반환한다.
func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

// OffsetClock 은 기준 Clock 에 특정 오프셋(Duration)을 더해 시계를 가상 조작하는 Clock 구현체다.
type OffsetClock struct {
	Base   Clock
	Offset time.Duration
}

// NewOffsetClock 은 base 클럭과 offset 기간을 받아 OffsetClock 을 생성한다.
func NewOffsetClock(base Clock, offset time.Duration) *OffsetClock {
	if base == nil {
		base = RealClock{}
	}
	return &OffsetClock{
		Base:   base,
		Offset: offset,
	}
}

// Now 는 가상 조작된 시각을 반환한다.
func (c *OffsetClock) Now() time.Time {
	return c.Base.Now().Add(c.Offset)
}

// ActorClaim 은 RFC 8693 Token Exchange §4.1 에 따른 위임 주체(Actor) 계보 클레임이다.
type ActorClaim struct {
	Subject string      `json:"sub"`
	JWTID   string      `json:"jti,omitempty"`
	Actor   *ActorClaim `json:"act,omitempty"`
}

// TokenClaims 는 RFC 9068 표준 Bearer Access Token 클레임 세트다.
type TokenClaims struct {
	Issuer          string      `json:"iss"`
	Subject         string      `json:"sub"`
	Audience        string      `json:"aud"`
	ClientID        string      `json:"client_id"`
	ExpiresAt       int64       `json:"exp"`
	IssuedAt        int64       `json:"iat"`
	NotBefore       int64       `json:"nbf"`
	JWTID           string      `json:"jti"`
	Scope           string      `json:"scope"`
	Epoch           Epoch       `json:"epoch"`
	Actor           *ActorClaim `json:"act,omitempty"`
	DelegationDepth int         `json:"delegation_depth,omitempty"`
}

// Validate 는 필수 클레임 및 기본 유효성을 검증한다.
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
	return nil
}

// VerifiedClaims 는 Gate 1 암호학적 서명 및 클레임 검증을 통과한 신뢰 토큰 정보다.
type VerifiedClaims struct {
	Claims    TokenClaims `json:"claims"`
	KeyID     string      `json:"kid"`
	Algorithm string      `json:"alg"`
	VerifiedAt time.Time   `json:"verified_at"`
}
