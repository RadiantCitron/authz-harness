package pep_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// budgetPEP 는 setupTestHarness 위에 예산 원장을 가진 PEP 를 추가로 만든다.
func budgetPEP(t *testing.T, h *testHarness, withLedger bool) (pep.Gateway, *budget.FileLedger) {
	t.Helper()
	ledger, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "budget_ledger.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := pep.Config{Verifier: h.verifier, PDP: h.pdpSvc, Jail: h.jailInst, AuditWriter: h.auditWriter}
	if withLedger {
		cfg.BudgetLedger = ledger
	}
	gw, err := pep.NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return gw, ledger
}

// issueBudgetToken 은 루트 예산 토큰을 서명하고 원장(ledger)에 직접 등록한다(발급자 배선은 030에서 검증됨).
func issueBudgetToken(t *testing.T, h *testHarness, ledger *budget.FileLedger, b domain.Budget, register bool) *token.IssueResult {
	t.Helper()
	res, err := h.tokenIssuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Audience: "authz-harness",
		Scope: "file:read:docs/a.txt file:write:docs/out.txt", TTL: time.Hour, Epoch: 1,
		Budget: &b,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "t", Actor: "t"})
	if err == nil {
		t.Fatal("issuer without ledger must refuse budget root (fail-closed)")
	}
	_ = res
	// 원장 없는 발급자는 거부하므로, 원장이 있는 발급자를 별도로 구성한다.
	iss := token.NewService(h.keyMgr, token.NewInMemoryClientRegistry(), h.auditWriter, domain.RealClock{},
		token.WithBudgetLedger(ledgerOrDiscard(t, ledger, register)))
	res, err = iss.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Audience: "authz-harness",
		Scope: "file:read:docs/a.txt file:write:docs/out.txt", TTL: time.Hour, Epoch: 1,
		Budget: &b,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "t", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// ledgerOrDiscard: register=false 면 다른(빈) 원장에 등록해 PEP 원장에는 엔트리가 없게 한다.
func ledgerOrDiscard(t *testing.T, l *budget.FileLedger, register bool) budget.Ledger {
	if register {
		return l
	}
	other, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "other.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	return other
}

func grantAll(t *testing.T, h *testHarness) {
	t.Helper()
	createGrant(t, h, "worker-01", domain.ActionFileRead, "docs/a.txt")
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/out.txt")
}

func writeFixture(t *testing.T, h *testHarness, rel, content string) {
	t.Helper()
	p := filepath.Join(h.workspaceDir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func exec(t *testing.T, gw pep.Gateway, tok string, act domain.Action, res string, data []byte, injectAudit bool) *pep.Result {
	t.Helper()
	r, err := gw.Execute(context.Background(), pep.Request{
		Token: tok, Action: act, Resource: res, Data: data, InjectAuditFailure: injectAudit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func remainingOf(t *testing.T, l *budget.FileLedger, jti string) domain.Budget {
	t.Helper()
	e, ok, err := l.Get(jti)
	if err != nil || !ok {
		t.Fatalf("ledger Get: ok=%v err=%v", ok, err)
	}
	return e.Remaining
}

func TestBudget_ReadCallsExhausted(t *testing.T) { // TC-040-01
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "hello")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 1}, true)

	if r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false); r.ExitCode != domain.ExitSuccess {
		t.Fatalf("1st: %+v", r)
	}
	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	if r.ExitCode != domain.ExitAuthzDenied || r.Reason != domain.ReasonBudgetExhausted {
		t.Fatalf("2nd: exit=%d reason=%s", r.ExitCode, r.Reason)
	}
	if len(r.Data) != 0 {
		t.Fatal("denied read must not return data")
	}
}

func TestBudget_WriteBytesExceeded(t *testing.T) { // TC-040-02
	h := setupTestHarness(t)
	grantAll(t, h)
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5, MaxWriteBytes: 10}, true)

	r := exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", make([]byte, 11), false)
	if r.ExitCode != domain.ExitAuthzDenied || r.Reason != domain.ReasonBudgetExhausted || r.Stage != domain.StageBudget {
		t.Fatalf("got exit=%d reason=%s stage=%s", r.ExitCode, r.Reason, r.Stage)
	}
	if _, err := os.Stat(filepath.Join(h.workspaceDir, "docs/out.txt")); err == nil {
		t.Fatal("file must not be created")
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 5 || rem.MaxWriteBytes != 10 {
		t.Fatalf("remaining changed: %+v", rem)
	}
}

func TestBudget_ReadBytesExceeded(t *testing.T) { // TC-040-03
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "01234567890123456789")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5, MaxReadBytes: 5}, true)

	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	if r.ExitCode != domain.ExitAuthzDenied || r.Reason != domain.ReasonBudgetExhausted || len(r.Data) != 0 {
		t.Fatalf("got exit=%d reason=%s data=%d", r.ExitCode, r.Reason, len(r.Data))
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 5 || rem.MaxReadBytes != 5 {
		t.Fatalf("failed read consumed budget: %+v", rem)
	}
}

func TestBudget_RefundOnAuditFailure(t *testing.T) { // TC-040-04
	h := setupTestHarness(t)
	grantAll(t, h)
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5, MaxWriteBytes: 10}, true)

	r := exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", make([]byte, 5), true)
	if r.Allowed || r.Reason != domain.ReasonAuditLogFailed {
		t.Fatalf("got %+v", r)
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 5 || rem.MaxWriteBytes != 10 {
		t.Fatalf("not refunded: %+v", rem)
	}
	if _, err := os.Stat(filepath.Join(h.workspaceDir, "docs/out.txt")); err == nil {
		t.Fatal("file must not exist")
	}
	// 정상 쓰기는 차감이 유지된다
	if r := exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", make([]byte, 5), false); !r.Allowed {
		t.Fatalf("write: %+v", r)
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 4 || rem.MaxWriteBytes != 5 {
		t.Fatalf("after success: %+v", rem)
	}
}

func TestBudget_NoLedgerEntry(t *testing.T) { // TC-040-05
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "x")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3}, false)

	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	if r.ExitCode != domain.ExitAuthzDenied || r.Reason != domain.ReasonBudgetExhausted || len(r.Data) != 0 {
		t.Fatalf("read: exit=%d reason=%s", r.ExitCode, r.Reason)
	}
	r = exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", []byte("x"), false)
	if r.Reason != domain.ReasonBudgetExhausted || r.Stage != domain.StageBudget {
		t.Fatalf("write: reason=%s stage=%s", r.Reason, r.Stage)
	}
}

func TestBudget_PEPWithoutLedgerFailClosed(t *testing.T) { // TC-040-06
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "x")
	_, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3}, true)
	gw, _ := budgetPEP(t, h, false)

	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	if r.ExitCode != domain.ExitInternalError || r.Stage != domain.StageAuthn {
		t.Fatalf("got exit=%d stage=%s", r.ExitCode, r.Stage)
	}
}

func TestBudget_NilBudgetTokenKeepsReplay(t *testing.T) { // TC-040-07
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "x")
	gw, _ := budgetPEP(t, h, true)
	tok := issueValidToken(t, h, "worker-01", "file:read:docs/a.txt", time.Hour, 1)

	if r := exec(t, gw, tok, domain.ActionFileRead, "docs/a.txt", nil, false); !r.Allowed {
		t.Fatalf("1st: %+v", r)
	}
	r := exec(t, gw, tok, domain.ActionFileRead, "docs/a.txt", nil, false)
	if r.ExitCode != domain.ExitTokenInvalid || r.Reason != domain.ReasonTokenReplayDetected {
		t.Fatalf("2nd: exit=%d reason=%s", r.ExitCode, r.Reason)
	}
}

// 읽기 사후 차감 실패 시 감사 순서: precommit_audit 단계 사전 감사(allow) 뒤에 거부 감사(deny)가 따라붙는다.
func TestBudget_ReadDenyAuditOrder(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "0123456789")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3, MaxReadBytes: 2}, true)

	r, err := gw.Execute(context.Background(), pep.Request{
		Token: tok.TokenString, Action: domain.ActionFileRead, Resource: "docs/a.txt", TraceID: "order-trace",
	})
	if err != nil || r.Allowed {
		t.Fatalf("want deny, got %+v err=%v", r, err)
	}
	f, err := os.Open(h.auditFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var seq []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var ev struct {
			TraceID string `json:"trace_id"`
			Action  string `json:"action"`
			Stage   string `json:"stage"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.TraceID == "order-trace" && (ev.Action == "pep.allow" || ev.Action == "pep.deny") {
			seq = append(seq, ev.Action+"@"+ev.Stage)
		}
	}
	want := []string{"pep.allow@precommit_audit", "pep.deny@settle"}
	if len(seq) != 2 || seq[0] != want[0] || seq[1] != want[1] {
		t.Fatalf("audit order = %v, want %v", seq, want)
	}
}
