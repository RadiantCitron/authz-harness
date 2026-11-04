package exchange_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

type failWriter struct{}

func (failWriter) Log(audit.Event) error { return errors.New("audit down") }
func (failWriter) Close() error          { return nil }

func TestExchange_DenyAuditFailureFailsClosed(t *testing.T) { // TC-020-03③
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	_, issuer, verifier, _, _, _, clk := setupTestHarness(t, now)
	svc := exchange.NewExchangeService(issuer, verifier, token.NewInMemoryClientRegistry(), exchange.NewDownscopeValidator(), failWriter{}, clk)
	_, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02", ParentToken: "x", ChildSubject: "",
	}, domain.AuditContext{})
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("got %v", err)
	}
}
