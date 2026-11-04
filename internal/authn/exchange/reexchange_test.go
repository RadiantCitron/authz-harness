package exchange_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

type rxEnv struct {
	svc      *exchange.ExchangeService
	issuer   *token.Service
	clk      *mutableClock
	auditP   string
	baseTime time.Time
}

func newRxEnv(t *testing.T) *rxEnv {
	t.Helper()
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, auditP, clk := setupTestHarness(t, base)
	return &rxEnv{svc, issuer, clk, auditP, base}
}

func (e *rxEnv) parent(t *testing.T, epoch domain.Epoch, ttl time.Duration) *token.IssueResult {
	t.Helper()
	r, err := e.issuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "lead-01", Scope: "file:read:docs/a.txt", TTL: ttl, Epoch: epoch,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent issue: %v", err)
	}
	return r
}

func (e *rxEnv) exch(parent, sub string, ttl time.Duration, childEpoch domain.Epoch) (*exchange.ExchangeResult, error) {
	return e.svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: parent, ChildSubject: sub, Scope: "file:read:docs/a.txt",
		TTL: ttl, ChildEpoch: childEpoch,
	}, domain.AuditContext{})
}

func (e *rxEnv) auditHas(t *testing.T, action string) bool {
	t.Helper()
	b, err := os.ReadFile(e.auditP)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), action)
}

func wantDomainErr(t *testing.T, err error, reason domain.Reason, exit domain.ExitCode) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("want domain error %s, got %v", reason, err)
	}
	if de.Reason != reason || de.ExitCode != exit {
		t.Fatalf("got %s/%d, want %s/%d", de.Reason, de.ExitCode, reason, exit)
	}
}

func TestReExchange_EpochSeparation(t *testing.T) { // TC-030-01, 02
	cases := []struct {
		name       string
		childEpoch domain.Epoch
		want       domain.Epoch
	}{
		{"TC-030-01 ChildEpoch 1 지정, 부모 Epoch 2는 act 에 보존", 1, 1},
		{"TC-030-02 ChildEpoch 미지정은 1", 0, 1},
		{"자식 Epoch 3 지정", 3, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRxEnv(t)
			p := e.parent(t, 2, time.Hour)
			r, err := e.exch(p.TokenString, "worker-01", 5*time.Minute, tc.childEpoch)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			if r.Claims.Epoch != tc.want {
				t.Errorf("child epoch = %d, want %d", r.Claims.Epoch, tc.want)
			}
			if r.Claims.Actor == nil || r.Claims.Actor.Epoch != 2 {
				t.Errorf("act.epoch = %+v, want 2", r.Claims.Actor)
			}
		})
	}
}

func TestReExchange_Lifecycle(t *testing.T) {
	t.Run("TC-030-03 자식 만료 후 같은 부모로 재교환", func(t *testing.T) {
		e := newRxEnv(t)
		p := e.parent(t, 1, 30*time.Minute)
		c1, err := e.exch(p.TokenString, "worker-01", 5*time.Minute, 1)
		if err != nil {
			t.Fatal(err)
		}
		e.clk.Set(e.baseTime.Add(6 * time.Minute))
		c2, err := e.exch(p.TokenString, "worker-01", 5*time.Minute, 1)
		if err != nil {
			t.Fatalf("re-exchange: %v", err)
		}
		if c2.Claims.JWTID == c1.Claims.JWTID {
			t.Error("jti must differ")
		}
		if want := e.baseTime.Add(6 * time.Minute).Unix(); c2.Claims.IssuedAt != want {
			t.Errorf("iat = %d, want %d", c2.Claims.IssuedAt, want)
		}
		if c2.Claims.ExpiresAt > p.Claims.ExpiresAt {
			t.Error("child exp must not exceed parent exp")
		}
		if !e.auditHas(t, "token.exchanged") {
			t.Error("token.exchanged audit missing")
		}
	})

	t.Run("TC-030-04 부모 잔여 수명 초과 TTL 재교환 거부", func(t *testing.T) {
		e := newRxEnv(t)
		p := e.parent(t, 1, 10*time.Minute)
		e.clk.Set(e.baseTime.Add(8 * time.Minute)) // 잔여 2분
		_, err := e.exch(p.TokenString, "worker-01", 5*time.Minute, 1)
		wantDomainErr(t, err, domain.ReasonDelegationTTLExceeded, domain.ExitAuthzDenied)
		if !e.auditHas(t, "token.exchange.deny") {
			t.Error("token.exchange.deny audit missing")
		}
	})

	t.Run("TC-030-05 부모 만료 후 재교환 거부", func(t *testing.T) {
		e := newRxEnv(t)
		p := e.parent(t, 1, 10*time.Minute)
		e.clk.Set(e.baseTime.Add(11 * time.Minute))
		_, err := e.exch(p.TokenString, "worker-01", 5*time.Minute, 1)
		wantDomainErr(t, err, domain.ReasonTokenExpired, domain.ExitTokenInvalid)
		if !e.auditHas(t, "token.exchange.deny") {
			t.Error("token.exchange.deny audit missing")
		}
	})

	t.Run("TC-030-06 자식 토큰으로 자기 자신에게 교환은 자기 순환 거부", func(t *testing.T) {
		e := newRxEnv(t)
		p := e.parent(t, 1, time.Hour)
		c, err := e.exch(p.TokenString, "worker-01", 5*time.Minute, 1)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.exch(c.TokenString, "worker-01", time.Minute, 1)
		wantDomainErr(t, err, domain.ReasonDelegationSelfLoop, domain.ExitAuthzDenied)
	})
}
