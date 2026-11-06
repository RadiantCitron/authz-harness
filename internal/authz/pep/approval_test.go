package pep_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

func askPEP(t *testing.T, h *testHarness, withConsumer bool, aw audit.Writer, ledger budget.Ledger) pep.Gateway {
	t.Helper()
	if aw == nil {
		aw = h.auditWriter
	}
	cfg := pep.Config{Verifier: h.verifier, PDP: h.pdpSvc, Jail: h.jailInst, AuditWriter: aw, BudgetLedger: ledger}
	if withConsumer {
		cfg.ApprovalConsumer = state.NewApprovalConsumer(h.store)
	}
	gw, err := pep.NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return gw
}

func approvalGrant(t *testing.T, h *testHarness, sub, res string) {
	t.Helper()
	if _, err := h.papSvc.CreateGrant(context.Background(), pap.CreateGrantRequest{
		Subject: sub, Action: domain.ActionFileWrite, Resource: res, RequiresApproval: true}); err != nil {
		t.Fatal(err)
	}
}

func approve(t *testing.T, h *testHarness, sub, res, jti string, data []byte) {
	t.Helper()
	if _, err := h.papSvc.CreateApproval(context.Background(), pap.CreateApprovalRequest{
		Subject: sub, Action: domain.ActionFileWrite, Resource: res, TokenJTI: jti, ArgHash: domain.DataDigest(data)}); err != nil {
		t.Fatal(err)
	}
}

func writeReq(tok, res string, data []byte) pep.Request {
	return pep.Request{Token: tok, Action: domain.ActionFileWrite, Resource: res, Data: data}
}

func approvalCount(t *testing.T, h *testHarness) int {
	t.Helper()
	st, err := h.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return len(st.Approvals)
}

func auditActions(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]interface{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]interface{}
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func fileExists(h *testHarness, rel string) bool {
	_, err := os.Stat(filepath.Join(h.workspaceDir, rel))
	return err == nil
}

func TestPEPAskThenApproveRetry(t *testing.T) { // TC-040-01
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	sub, res, data := "worker-01", "docs/s.txt", []byte("hello")
	approvalGrant(t, h, sub, res)
	tok := issueValidToken(t, h, sub, "file:write:"+res, time.Hour, 1)

	r1, _ := gw.Execute(context.Background(), writeReq(tok, res, data))
	if r1.ExitCode != domain.ExitApprovalRequired || r1.Reason != domain.ReasonApprovalRequired || r1.Stage != domain.StageAuthz || r1.TokenJTI == "" {
		t.Fatalf("first: %+v", r1)
	}
	if fileExists(h, res) {
		t.Fatal("ask must not touch the file")
	}
	var sawAsk bool
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "pep.deny" && ev["decision"] == "ask" && ev["reason"] == "APPROVAL_REQUIRED" {
			sawAsk = true
		}
	}
	if !sawAsk {
		t.Fatal("pep.deny/ask audit missing")
	}

	approve(t, h, sub, res, r1.TokenJTI, data)
	r2, _ := gw.Execute(context.Background(), writeReq(tok, res, data))
	if !r2.Allowed || r2.ExitCode != domain.ExitSuccess {
		t.Fatalf("retry: %+v", r2)
	}
	if !fileExists(h, res) || approvalCount(t, h) != 0 {
		t.Fatal("file must be written and approval consumed")
	}
	var consumed bool
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "approval.consumed" {
			consumed = true
		}
	}
	if !consumed {
		t.Fatal("approval.consumed audit missing")
	}
	// 승인은 1회용이고 jti 도 소비되었으므로 같은 토큰 3차 호출은 11
	if r3, _ := gw.Execute(context.Background(), writeReq(tok, res, data)); r3.ExitCode != domain.ExitTokenInvalid {
		t.Fatalf("third: %+v", r3)
	}
}

func TestPEPReplayAfterSuccess(t *testing.T) { // TC-040-02
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/p.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/p.txt", time.Hour, 1)
	if r, _ := gw.Execute(context.Background(), writeReq(tok, "docs/p.txt", []byte("x"))); !r.Allowed {
		t.Fatalf("%+v", r)
	}
	r, _ := gw.Execute(context.Background(), writeReq(tok, "docs/p.txt", []byte("x")))
	if r.ExitCode != domain.ExitTokenInvalid || r.Stage != domain.StageAuthn || r.Reason != domain.ReasonTokenReplayDetected {
		t.Fatalf("%+v", r)
	}
}

func TestPEPConcurrentSameToken(t *testing.T) { // TC-040-03
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/c.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/c.txt", time.Hour, 1)
	var wg sync.WaitGroup
	codes := make([]domain.ExitCode, 2)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := gw.Execute(context.Background(), writeReq(tok, "docs/c.txt", []byte("x")))
			codes[i] = r.ExitCode
		}()
	}
	wg.Wait()
	ok, rep := 0, 0
	for _, c := range codes {
		switch c {
		case domain.ExitSuccess:
			ok++
		case domain.ExitTokenInvalid:
			rep++
		}
	}
	if ok != 1 || rep != 1 {
		t.Fatalf("codes = %v", codes)
	}
}

func TestPEPDenyDoesNotConsumeJTI(t *testing.T) { // TC-040-04
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/d.txt", time.Hour, 1)
	if r, _ := gw.Execute(context.Background(), writeReq(tok, "docs/d.txt", []byte("x"))); r.ExitCode != domain.ExitAuthzDenied {
		t.Fatalf("first: %+v", r)
	}
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/d.txt")
	if r, _ := gw.Execute(context.Background(), writeReq(tok, "docs/d.txt", []byte("x"))); !r.Allowed {
		t.Fatalf("second: %+v", r)
	}
}

func TestPEPJailViolationKeepsApproval(t *testing.T) { // TC-040-05
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(h.workspaceDir, "link")); err != nil {
		t.Fatal(err)
	}
	const res = "link/x.txt" // Grant 검증은 통과하지만 Jail 이 심볼릭 링크 탈출로 막는다
	approvalGrant(t, h, "worker-01", res)
	tok := issueValidToken(t, h, "worker-01", "file:write:"+res, time.Hour, 1)
	r0, _ := gw.Execute(context.Background(), writeReq(tok, res, []byte("x")))
	if r0.ExitCode != domain.ExitApprovalRequired {
		t.Fatalf("ask: %+v", r0)
	}
	approve(t, h, "worker-01", res, r0.TokenJTI, []byte("x"))
	r, _ := gw.Execute(context.Background(), writeReq(tok, res, []byte("x")))
	if r.ExitCode != domain.ExitPathViolation || r.Stage != domain.StageBoundary {
		t.Fatalf("%+v", r)
	}
	if approvalCount(t, h) != 1 {
		t.Fatal("path violation must not consume the approval")
	}
	if _, err := os.Stat(filepath.Join(outside, "x.txt")); err == nil {
		t.Fatal("file escaped the jail")
	}
}

func TestPEPBudgetTokenApprovalSingleUse(t *testing.T) { // TC-040-06
	h := setupTestHarness(t)
	ledger, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "budget_ledger.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	gw := askPEP(t, h, true, nil, ledger)
	approvalGrant(t, h, "worker-01", "docs/out.txt")
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 2}, true)
	data := []byte("x")
	// jti 를 알아야 승인을 만들 수 있으므로 먼저 ask 로 받아온다.
	r0, _ := gw.Execute(context.Background(), writeReq(tok.TokenString, "docs/out.txt", data))
	if r0.ExitCode != domain.ExitApprovalRequired {
		t.Fatalf("ask: %+v", r0)
	}
	approve(t, h, "worker-01", "docs/out.txt", r0.TokenJTI, data)
	if r, _ := gw.Execute(context.Background(), writeReq(tok.TokenString, "docs/out.txt", data)); !r.Allowed {
		t.Fatalf("first: %+v", r)
	}
	r2, _ := gw.Execute(context.Background(), writeReq(tok.TokenString, "docs/out.txt", data))
	if r2.ExitCode != domain.ExitApprovalRequired || r2.Reason != domain.ReasonApprovalRequired {
		t.Fatalf("second: %+v", r2)
	}
	e, found, err := ledger.Get(r0.TokenJTI)
	if err != nil || !found || e.Remaining.MaxCalls != 1 {
		t.Fatalf("budget must be charged once: %+v found=%v err=%v", e, found, err)
	}
}

type failAfterWriter struct {
	inner audit.Writer
	hit   string
}

func (f failAfterWriter) Log(ev audit.Event) error {
	if ev.Action == f.hit {
		return errors.New("injected")
	}
	return f.inner.Log(ev)
}
func (f failAfterWriter) Close() error { return nil }

func TestPEPApprovalAuditFailure(t *testing.T) { // TC-040-07
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, failAfterWriter{inner: h.auditWriter, hit: "approval.consumed"}, nil)
	approvalGrant(t, h, "worker-01", "docs/s.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/s.txt", time.Hour, 1)
	r0, _ := gw.Execute(context.Background(), writeReq(tok, "docs/s.txt", []byte("x")))
	approve(t, h, "worker-01", "docs/s.txt", r0.TokenJTI, []byte("x"))
	r, _ := gw.Execute(context.Background(), writeReq(tok, "docs/s.txt", []byte("x")))
	if r.ExitCode != domain.ExitAuditFailure {
		t.Fatalf("%+v", r)
	}
	if approvalCount(t, h) != 0 || fileExists(h, "docs/s.txt") {
		t.Fatal("approval must be gone and file untouched")
	}
}

func TestAuditNormalizeKeepsAsk(t *testing.T) { // TC-040-08
	ev := audit.Event{Decision: "ask"}
	audit.NormalizeEvent(&ev)
	if ev.Decision != "ask" {
		t.Fatalf("decision = %q", ev.Decision)
	}
}

func TestPEPNoApprovalConsumerFailsClosed(t *testing.T) { // TC-040-09
	h := setupTestHarness(t)
	gw := askPEP(t, h, false, nil, nil)
	approvalGrant(t, h, "worker-01", "docs/s.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/s.txt", time.Hour, 1)
	r0, _ := gw.Execute(context.Background(), writeReq(tok, "docs/s.txt", []byte("x")))
	approve(t, h, "worker-01", "docs/s.txt", r0.TokenJTI, []byte("x"))
	r, _ := gw.Execute(context.Background(), writeReq(tok, "docs/s.txt", []byte("x")))
	if r.ExitCode != domain.ExitInternalError || fileExists(h, "docs/s.txt") {
		t.Fatalf("%+v", r)
	}
}
