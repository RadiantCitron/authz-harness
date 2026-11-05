package exchange_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/keys"
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

type mockSnapshotProvider struct {
	epochs domain.SecurityEpochs
}

func (m *mockSnapshotProvider) GetSubjectSnapshot(_ context.Context, subject string) (*domain.SubjectSnapshot, error) {
	return &domain.SubjectSnapshot{
		Subject:       subject,
		CurrentEpoch:  m.epochs.Get(subject),
		SubjectEpochs: m.epochs,
	}, nil
}

func (m *mockSnapshotProvider) GetActiveGrants(_ context.Context, _ string) ([]domain.Grant, error) {
	return nil, nil
}

func (m *mockSnapshotProvider) GetCurrentEpoch(_ context.Context, subject string) (domain.Epoch, error) {
	return m.epochs.Get(subject), nil
}

func TestExchange_WithSnapshotProvider_EarlyEpochRejection(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	st, err := keys.NewFileStore(filepath.Join(dir, "priv.json"), filepath.Join(dir, "pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	auditP := filepath.Join(dir, "audit.jsonl")
	auditW, err := audit.NewJSONLWriter(auditP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditW.Close() })
	keyMgr, err := keys.NewManager(st, auditW)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyMgr.RotateKey(domain.AuditContext{TraceID: "init", Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	clk := &mutableClock{t: baseTime}
	replay, err := token.NewFileReplayLedger(filepath.Join(dir, "replay.json"), clk)
	if err != nil {
		t.Fatal(err)
	}
	clients := token.NewInMemoryClientRegistry()
	issuer := token.NewService(keyMgr, clients, auditW, clk)
	verifier := token.NewVerifier(keyMgr, replay, auditW, clk)
	validator := exchange.NewDownscopeValidator()

	sp := &mockSnapshotProvider{
		epochs: domain.SecurityEpochs{
			"lead-01":   1,
			"mid-01":    1,
			"worker-01": 1,
		},
	}
	svc := exchange.NewExchangeService(
		issuer,
		verifier,
		clients,
		validator,
		auditW,
		clk,
		exchange.WithSnapshotProvider(sp),
	)

	// 1. lead-01 (Epoch 1) -> mid-01 교환 성공
	p0, err := issuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "lead-01", Scope: "file:read:docs/a.txt", TTL: time.Hour, Epoch: 1,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}

	p1, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		ParentToken: p0.TokenString, ChildSubject: "mid-01", Scope: "file:read:docs/a.txt", TTL: 30 * time.Minute,
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("expected p0->p1 exchange to succeed: %v", err)
	}

	// 2. 상위 위임자(lead-01)의 Epoch를 2로 Bump한 뒤 mid-01 토큰(p1)으로 worker-01 교환 시도 -> 조상 Epoch 불일치로 즉시 거부
	sp.epochs["lead-01"] = 2
	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: p1.TokenString, ChildSubject: "worker-01", Scope: "file:read:docs/a.txt", TTL: 10 * time.Minute,
	}, domain.AuditContext{TraceID: "trc-epoch-anc"})
	wantDomainErr(t, err, domain.ReasonSubjectEpochRevoked, domain.ExitAuthzDenied)

	// 3. 직계 부모(p0, lead-01 Epoch 1)로 직접 교환 시도 -> 직계 부모 Epoch 불일치로 즉시 거부
	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: p0.TokenString, ChildSubject: "worker-01", Scope: "file:read:docs/a.txt", TTL: 10 * time.Minute,
	}, domain.AuditContext{TraceID: "trc-epoch-parent"})
	wantDomainErr(t, err, domain.ReasonSubjectEpochRevoked, domain.ExitAuthzDenied)
}
