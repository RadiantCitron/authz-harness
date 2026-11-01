package domain

import (
	"testing"
	"time"
)

func TestTokenClaims_Validate(t *testing.T) {
	now := time.Now().Unix()
	validClaims := TokenClaims{
		Issuer:    "authz-harness",
		Subject:   "worker-01",
		Audience:  "authz-service",
		ClientID:  "client-orchestrator",
		ExpiresAt: now + 3600,
		IssuedAt:  now,
		NotBefore: now,
		JWTID:     "test-jti-001",
		Scope:     "file:read:docs/plan.txt",
		Epoch:     1,
	}

	if err := validClaims.Validate(); err != nil {
		t.Fatalf("expected valid claims, got error: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(c *TokenClaims)
		wantErr bool
	}{
		{
			name: "iss 누락",
			mutate: func(c *TokenClaims) {
				c.Issuer = ""
			},
			wantErr: true,
		},
		{
			name: "sub 누락",
			mutate: func(c *TokenClaims) {
				c.Subject = ""
			},
			wantErr: true,
		},
		{
			name: "aud 누락",
			mutate: func(c *TokenClaims) {
				c.Audience = ""
			},
			wantErr: true,
		},
		{
			name: "client_id 누락",
			mutate: func(c *TokenClaims) {
				c.ClientID = ""
			},
			wantErr: true,
		},
		{
			name: "jti 누락",
			mutate: func(c *TokenClaims) {
				c.JWTID = ""
			},
			wantErr: true,
		},
		{
			name: "exp <= iat 오류",
			mutate: func(c *TokenClaims) {
				c.ExpiresAt = c.IssuedAt
			},
			wantErr: true,
		},
		{
			name: "epoch < 1 오류",
			mutate: func(c *TokenClaims) {
				c.Epoch = 0
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validClaims
			tt.mutate(&c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOffsetClock(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	mock := &mockClock{fixed: baseTime}

	offsetClock := NewOffsetClock(mock, 2*time.Hour)
	got := offsetClock.Now()
	expected := baseTime.Add(2 * time.Hour)
	if !got.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}

type mockClock struct {
	fixed time.Time
}

func (m *mockClock) Now() time.Time {
	return m.fixed
}
