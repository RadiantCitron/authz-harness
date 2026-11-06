package pep_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
	"authz-harness/internal/execguard"
	"authz-harness/internal/jail"
	"authz-harness/internal/netguard"
	"authz-harness/internal/subagent"
)

// spyJail 은 Jail 호출 횟수를 센다(새 도구가 Jail 을 건드리지 않음을 확인).
type spyJail struct {
	jail.Jail
	calls int32
}

func (s *spyJail) ResolvePath(p string, w bool) (string, error) {
	atomic.AddInt32(&s.calls, 1)
	return s.Jail.ResolvePath(p, w)
}
func (s *spyJail) ReadFile(p string) ([]byte, error) {
	atomic.AddInt32(&s.calls, 1)
	return s.Jail.ReadFile(p)
}
func (s *spyJail) WriteFile(p string, d []byte) error {
	atomic.AddInt32(&s.calls, 1)
	return s.Jail.WriteFile(p, d)
}

type toolOpts struct {
	allow   []string
	noNet   bool
	noExec  bool
	jail    jail.Jail
	ledger  budget.Ledger
	observe func(domain.Stage)
}

func toolPEP(t *testing.T, h *testHarness, o toolOpts) pep.Gateway {
	t.Helper()
	cfg := pep.Config{
		Verifier: h.verifier, PDP: h.pdpSvc, Jail: h.jailInst, AuditWriter: h.auditWriter,
		ApprovalConsumer: state.NewApprovalConsumer(h.store),
		BudgetLedger:     o.ledger, StageObserver: o.observe,
	}
	if o.jail != nil {
		cfg.Jail = o.jail
	}
	if !o.noNet {
		g, err := netguard.NewGuard(o.allow, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		cfg.NetGuard = g
	}
	if !o.noExec {
		cfg.ExecRunner = execguard.NewRunner(h.workspaceDir, 0, 0)
	}
	gw, err := pep.NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return gw
}

func fakeServer(t *testing.T, body string) (*httptest.Server, string, *int32) {
	t.Helper()
	var n int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	return s, u.Host, &n
}

func netReq(tok, u string) pep.Request {
	return pep.Request{Token: tok, Action: domain.ActionNetFetch, Resource: u}
}

func execReq(tok, id, arg string) pep.Request {
	return pep.Request{Token: tok, Action: domain.ActionExecRun, Resource: id, Data: []byte(arg)}
}

func run(t *testing.T, gw pep.Gateway, r pep.Request) *pep.Result {
	t.Helper()
	res, err := gw.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func wantDeny(t *testing.T, r *pep.Result, code domain.ExitCode, reason domain.Reason, stage domain.Stage) {
	t.Helper()
	if r.Allowed || r.ExitCode != code || r.Reason != reason || r.Stage != stage {
		t.Fatalf("got allowed=%v exit=%d reason=%s stage=%s; want exit=%d reason=%s stage=%s", r.Allowed, r.ExitCode, r.Reason, r.Stage, code, reason, stage)
	}
}

// TC-040-01
func TestToolNetFetch_Allowed(t *testing.T) {
	h := setupTestHarness(t)
	_, hp, n := fakeServer(t, "status-ok")
	gw := toolPEP(t, h, toolOpts{allow: []string{hp}})
	createGrant(t, h, "worker-01", domain.ActionNetFetch, hp)
	tok := issueValidToken(t, h, "worker-01", "net:fetch:"+hp, time.Hour, 1)

	r := run(t, gw, netReq(tok, "http://"+hp+"/status"))
	if !r.Allowed || r.ExitCode != domain.ExitSuccess || string(r.Data) != "status-ok" || atomic.LoadInt32(n) != 1 {
		t.Fatalf("%+v data=%q reqs=%d", r, r.Data, atomic.LoadInt32(n))
	}
	var found bool
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "pep.allow" && ev["step"] == "pep.net:fetch" && ev["stage"] == string(domain.StageExecute) {
			found = true
			if ev["resource"] != hp || ev["arg_hash"] != domain.DataDigest([]byte("http://"+hp+"/status")) || ev["result_hash"] != domain.DataDigest([]byte("status-ok")) {
				t.Fatalf("audit mismatch: %v", ev)
			}
		}
	}
	if !found {
		t.Fatal("pep.allow audit for net:fetch missing")
	}
}

// TC-040-02
func TestToolNetFetch_ScopeMismatch(t *testing.T) {
	h := setupTestHarness(t)
	_, hp, n := fakeServer(t, "x")
	gw := toolPEP(t, h, toolOpts{allow: []string{hp}})
	createGrant(t, h, "worker-01", domain.ActionNetFetch, hp)
	tok := issueValidToken(t, h, "worker-01", "file:read:a.txt", time.Hour, 1)
	r := run(t, gw, netReq(tok, "http://"+hp+"/"))
	wantDeny(t, r, domain.ExitAuthzDenied, domain.ReasonTokenInsufficientScope, domain.StageAuthz)
	if atomic.LoadInt32(n) != 0 {
		t.Fatal("server must not be contacted")
	}
}

// TC-040-03
func TestToolDispatch_JailUntouched(t *testing.T) {
	h := setupTestHarness(t)
	_, hp, _ := fakeServer(t, "x")
	spy := &spyJail{Jail: h.jailInst}
	gw := toolPEP(t, h, toolOpts{allow: []string{hp}, jail: spy})
	createGrant(t, h, "worker-01", domain.ActionNetFetch, hp)
	createGrant(t, h, "worker-01", domain.ActionExecRun, "echo-safe")
	tok := issueValidToken(t, h, "worker-01", "net:fetch:"+hp+" exec:run:echo-safe", time.Hour, 1)
	if r := run(t, gw, netReq(tok, hp)); r.ExitCode != 0 {
		t.Fatalf("net: %+v", r)
	}
	tok2 := issueValidToken(t, h, "worker-01", "net:fetch:"+hp+" exec:run:echo-safe", time.Hour, 1)
	if r := run(t, gw, execReq(tok2, "echo-safe", "hi")); r.ExitCode != 0 {
		t.Fatalf("exec: %+v", r)
	}
	if atomic.LoadInt32(&spy.calls) != 0 {
		t.Fatalf("jail called %d times", spy.calls)
	}
}

// TC-040-04
func TestToolNetFetch_NotInAllowListDespiteGrant(t *testing.T) {
	h := setupTestHarness(t)
	_, p, _ := fakeServer(t, "x")
	_, q, nq := fakeServer(t, "x")
	gw := toolPEP(t, h, toolOpts{allow: []string{p}})
	createGrant(t, h, "worker-01", domain.ActionNetFetch, q)
	tok := issueValidToken(t, h, "worker-01", "net:fetch:"+q, time.Hour, 1)
	r := run(t, gw, netReq(tok, "http://"+q+"/"))
	wantDeny(t, r, domain.ExitAuthzDenied, domain.ReasonEgressDenied, domain.StageBoundary)
	if atomic.LoadInt32(nq) != 0 {
		t.Fatal("server Q must not be contacted")
	}
}

// TC-040-05
func TestToolNetFetch_BadURLNotAudited(t *testing.T) {
	h := setupTestHarness(t)
	gw := toolPEP(t, h, toolOpts{})
	r := run(t, gw, netReq("some.token.str", "http://127.0.0.1:8080@evil/?token=s3cr3t"))
	wantDeny(t, r, domain.ExitAuthzDenied, domain.ReasonEgressDenied, domain.StageInput)
	raw, err := os.ReadFile(h.auditFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cr3t") || strings.Contains(string(raw), "evil") {
		t.Fatal("raw URL leaked into audit")
	}
	var seen bool
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "pep.deny" && ev["resource"] == "<invalid-url>" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("deny audit with <invalid-url> missing")
	}
}

func budgetExecToken(t *testing.T, h *testHarness, l *budget.FileLedger, b domain.Budget) string {
	t.Helper()
	iss := token.NewService(h.keyMgr, token.NewInMemoryClientRegistry(), h.auditWriter, domain.RealClock{}, token.WithBudgetLedger(l))
	res, err := iss.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Audience: "authz-harness", Scope: "exec:run:echo-safe", TTL: time.Hour, Epoch: 1, Budget: &b,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "t", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return res.TokenString
}

// TC-040-06
func TestToolExec_BudgetPreDeduct(t *testing.T) {
	h := setupTestHarness(t)
	ledger, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "b.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	var stages []domain.Stage
	gw := toolPEP(t, h, toolOpts{ledger: ledger, observe: func(s domain.Stage) { stages = append(stages, s) }})
	createGrant(t, h, "worker-01", domain.ActionExecRun, "echo-safe")
	tok := budgetExecToken(t, h, ledger, domain.Budget{MaxCalls: 1})

	if r := run(t, gw, execReq(tok, "echo-safe", "a")); r.ExitCode != 0 {
		t.Fatalf("1st: %+v", r)
	}
	stages = nil
	r := run(t, gw, execReq(tok, "echo-safe", "a"))
	wantDeny(t, r, domain.ExitAuthzDenied, domain.ReasonBudgetExhausted, domain.StageBudget)
	for _, s := range stages {
		if s == domain.StageExecute {
			t.Fatal("Stage 5 must not be reached")
		}
	}
}

// TC-040-07
func TestToolNetFetch_ApprovalBindsURL(t *testing.T) {
	h := setupTestHarness(t)
	_, hp, _ := fakeServer(t, "page")
	gw := toolPEP(t, h, toolOpts{allow: []string{hp}})
	if _, err := h.papSvc.CreateGrant(context.Background(), pap.CreateGrantRequest{
		Subject: "worker-01", Action: domain.ActionNetFetch, Resource: hp, RequiresApproval: true}); err != nil {
		t.Fatal(err)
	}
	tok := issueValidToken(t, h, "worker-01", "net:fetch:"+hp, time.Hour, 1)

	r0 := run(t, gw, netReq(tok, "http://"+hp+"/status"))
	if r0.ExitCode != domain.ExitApprovalRequired || r0.TokenJTI == "" {
		t.Fatalf("ask: %+v", r0)
	}
	if _, err := h.papSvc.CreateApproval(context.Background(), pap.CreateApprovalRequest{
		Subject: "worker-01", Action: domain.ActionNetFetch, Resource: hp, TokenJTI: r0.TokenJTI,
		ArgHash: domain.DataDigest([]byte("http://" + hp + "/status"))}); err != nil {
		t.Fatal(err)
	}
	r1 := run(t, gw, netReq(tok, "http://"+hp+"/admin"))
	if r1.ExitCode != domain.ExitApprovalRequired || r1.Reason != domain.ReasonApprovalMismatch {
		t.Fatalf("/admin: %+v", r1)
	}
	r2 := run(t, gw, netReq(tok, "http://"+hp+"/status"))
	if !r2.Allowed || string(r2.Data) != "page" {
		t.Fatalf("/status: %+v", r2)
	}
}

// TC-040-08
func TestToolDispatch_UnwiredFailsClosed(t *testing.T) {
	h := setupTestHarness(t)
	_, hp, _ := fakeServer(t, "x")
	gw := toolPEP(t, h, toolOpts{allow: []string{hp}, noNet: true, noExec: true})
	createGrant(t, h, "worker-01", domain.ActionNetFetch, hp)
	createGrant(t, h, "worker-01", domain.ActionExecRun, "echo-safe")
	tok := issueValidToken(t, h, "worker-01", "net:fetch:"+hp+" exec:run:echo-safe", time.Hour, 1)
	wantDeny(t, run(t, gw, netReq(tok, hp)), domain.ExitInternalError, domain.ReasonInternalError, domain.StageBoundary)
	tok2 := issueValidToken(t, h, "worker-01", "net:fetch:"+hp+" exec:run:echo-safe", time.Hour, 1)
	wantDeny(t, run(t, gw, execReq(tok2, "echo-safe", "a")), domain.ExitInternalError, domain.ReasonInternalError, domain.StageBoundary)
}

// TC-040-09
func TestToolExec_Cases(t *testing.T) {
	h := setupTestHarness(t)
	gw := toolPEP(t, h, toolOpts{})
	for _, id := range []string{"echo-safe", "sh"} {
		createGrant(t, h, "worker-01", domain.ActionExecRun, id)
	}
	scope := "exec:run:echo-safe exec:run:sh"
	tok := func() string { return issueValidToken(t, h, "worker-01", scope, time.Hour, 1) }

	r := run(t, gw, execReq(tok(), "echo-safe", "hello_123"))
	if !r.Allowed || string(r.Data) != "hello_123\n" {
		t.Fatalf("ok: %+v %q", r, r.Data)
	}
	wantDeny(t, run(t, gw, execReq(tok(), "echo-safe", "-e")), domain.ExitAuthzDenied, domain.ReasonExecArgRejected, domain.StageBoundary)
	wantDeny(t, run(t, gw, execReq(tok(), "sh", "")), domain.ExitAuthzDenied, domain.ReasonExecNotAllowed, domain.StageBoundary)
}

// TC-040-10
func TestToolNetFetch_DataRejected(t *testing.T) {
	h := setupTestHarness(t)
	gw := toolPEP(t, h, toolOpts{})
	r := run(t, gw, pep.Request{Token: "x.y.z", Action: domain.ActionNetFetch, Resource: "127.0.0.1:8080", Data: []byte("x")})
	wantDeny(t, r, domain.ExitBadInput, domain.ReasonInvalidArguments, domain.StageInput)
}

// TC-040-11
func TestWorker_NewTools(t *testing.T) {
	h := setupTestHarness(t)
	_, hp, _ := fakeServer(t, "body!")
	gw := toolPEP(t, h, toolOpts{allow: []string{hp}})
	w, err := subagent.NewWorker(gw)
	if err != nil {
		t.Fatal(err)
	}
	createGrant(t, h, "worker-01", domain.ActionNetFetch, hp)
	createGrant(t, h, "worker-01", domain.ActionExecRun, "echo-safe")
	sc := "net:fetch:" + hp + " exec:run:echo-safe"

	resp, code := w.Execute(context.Background(), subagent.SubagentRequest{
		Token: issueValidToken(t, h, "worker-01", sc, time.Hour, 1), Action: "net:fetch", FilePath: hp, TraceID: "tr-1"})
	if code != 0 || resp.Output != "body!" || resp.BytesRead != 5 {
		t.Fatalf("net: %+v code=%d", resp, code)
	}
	resp, code = w.Execute(context.Background(), subagent.SubagentRequest{
		Token: issueValidToken(t, h, "worker-01", sc, time.Hour, 1), Action: "exec:run", FilePath: "echo-safe", Data: "hey", TraceID: "tr-2"})
	if code != 0 || resp.Output != "hey\n" || resp.BytesRead != 4 {
		t.Fatalf("exec: %+v code=%d", resp, code)
	}
}
