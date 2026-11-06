package pep_test

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

// 로드맵 19 / 040 인수 시험. 기대값은 ADR 0007·0008에서 도출했다(구현이 아니라 명세에서 가져옴).

func scopedBudgetToken(t *testing.T, h *testHarness, l *budget.FileLedger, scope string, b domain.Budget) string {
	t.Helper()
	iss := token.NewService(h.keyMgr, token.NewInMemoryClientRegistry(), h.auditWriter, domain.RealClock{}, token.WithBudgetLedger(l))
	res, err := iss.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Audience: "authz-harness", Scope: scope, TTL: time.Hour, Epoch: 1, Budget: &b,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "t", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return res.TokenString
}

func stageIDs(ss ...domain.Stage) []domain.Stage { return ss }

func equalStages(a, b []domain.Stage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TC-040-01: 정상 쓰기의 Passed
func TestConsumeAfterCheck_PlainWritePassed(t *testing.T) {
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/p.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/p.txt", time.Hour, 1)
	r := run(t, gw, writeReq(tok, "docs/p.txt", []byte("x")))
	want := stageIDs(domain.StageInput, domain.StageAuthn, domain.StageAuthz, domain.StageBoundary,
		domain.StageReplay, domain.StagePrecommitAudit, domain.StageExecute)
	if !r.Allowed || !equalStages(r.Passed, want) {
		t.Fatalf("allowed=%v passed=%v want %v", r.Allowed, r.Passed, want)
	}
}

// TC-040-02·03: 경계 위반은 jti 를 소비하지 않아 같은 토큰으로 정상 경로 재요청이 성공한다.
func TestConsumeAfterCheck_BoundaryViolationKeepsJTI(t *testing.T) {
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	if err := os.Symlink(t.TempDir(), filepath.Join(h.workspaceDir, "link")); err != nil {
		t.Fatal(err)
	}
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "link/x.txt")
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/ok.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:link/x.txt file:write:docs/ok.txt", time.Hour, 1)

	r := run(t, gw, writeReq(tok, "link/x.txt", []byte("x")))
	wantDeny(t, r, domain.ExitPathViolation, r.Reason, domain.StageBoundary)
	if r2 := run(t, gw, writeReq(tok, "docs/ok.txt", []byte("x"))); !r2.Allowed {
		t.Fatalf("retry with same token must succeed: %+v", r2)
	}
}

// TC-040-04: 승인 필요 요청이 경계에서 거부돼도 승인이 남고, 경로가 고쳐지면 같은 승인으로 재시도가 성공한다.
func TestConsumeAfterCheck_ApprovalSurvivesBoundaryViolation(t *testing.T) {
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	link := filepath.Join(h.workspaceDir, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	const res = "link/x.txt"
	approvalGrant(t, h, "worker-01", res)
	tok := issueValidToken(t, h, "worker-01", "file:write:"+res, time.Hour, 1)
	r0 := run(t, gw, writeReq(tok, res, []byte("x")))
	approve(t, h, "worker-01", res, r0.TokenJTI, []byte("x"))

	wantDeny(t, run(t, gw, writeReq(tok, res, []byte("x"))), domain.ExitPathViolation, domain.ReasonSymlinkEscape, domain.StageBoundary)
	if approvalCount(t, h) != 1 {
		t.Fatal("approval must remain")
	}
	// 경로를 고친다: 링크를 지우고 같은 이름의 실제 디렉터리를 만든다.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := run(t, gw, writeReq(tok, res, []byte("x"))); !r.Allowed {
		t.Fatalf("retry after fixing path: %+v", r)
	}
	if approvalCount(t, h) != 0 {
		t.Fatal("approval must be consumed by the successful retry")
	}
}

// TC-040-05: deny 에서는 예산이 변하지 않는다.
func TestConsumeAfterCheck_DenyLeavesBudget(t *testing.T) {
	h := setupTestHarness(t)
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3, MaxWriteBytes: 10}, true)
	r := exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", []byte("x"), false) // grant 없음
	if r.Allowed || r.Stage != domain.StageAuthz {
		t.Fatalf("%+v", r)
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 3 || rem.MaxWriteBytes != 10 {
		t.Fatalf("budget changed on deny: %+v", rem)
	}
}

// TC-040-11: 호출 예산이 소진된 토큰의 읽기는 budget 에서 막히고 사전 감사·읽기에 닿지 않는다.
func TestConsumeAfterCheck_ReadCallsExhaustedStopsAtBudget(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "hello")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 1}, true)
	exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)

	before := len(auditActions(t, h.auditFile))
	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	wantDeny(t, r, domain.ExitAuthzDenied, domain.ReasonBudgetExhausted, domain.StageBudget)
	for _, s := range r.Passed {
		if s == domain.StagePrecommitAudit || s == domain.StageExecute {
			t.Fatalf("passed %v", r.Passed)
		}
	}
	for _, ev := range auditActions(t, h.auditFile)[before:] {
		if ev["action"] == "pep.allow" {
			t.Fatalf("unexpected pep.allow after budget denial: %v", ev)
		}
	}
}

// TC-040-12: 호출 예산이 소진된 토큰의 net:fetch 는 대상 서버에 요청을 보내지 않는다.
func TestConsumeAfterCheck_NetFetchExhaustedSendsNoRequest(t *testing.T) {
	h := setupTestHarness(t)
	_, hp, n := fakeServer(t, "ok")
	ledger, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "b.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	gw := toolPEP(t, h, toolOpts{allow: []string{hp}, ledger: ledger})
	createGrant(t, h, "worker-01", domain.ActionNetFetch, hp)
	tok := scopedBudgetToken(t, h, ledger, "net:fetch:"+hp, domain.Budget{MaxCalls: 1})

	if r := run(t, gw, netReq(tok, "http://"+hp+"/a")); !r.Allowed {
		t.Fatalf("1st: %+v", r)
	}
	r := run(t, gw, netReq(tok, "http://"+hp+"/a"))
	wantDeny(t, r, domain.ExitAuthzDenied, domain.ReasonBudgetExhausted, domain.StageBudget)
	if got := atomic.LoadInt32(n); got != 1 {
		t.Fatalf("server requests = %d, want 1", got)
	}
}

// TC-040-13: 읽을 수 없는 파일 읽기는 execute 에서 실패하고 budget 의 호출분이 환급된다.
func TestConsumeAfterCheck_MissingFileRefundsCall(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	// 경계(존재 확인)는 통과하지만 읽기는 실패하는 파일: 읽기 권한 없음
	writeFixture(t, h, "docs/a.txt", "secret")
	if err := os.Chmod(filepath.Join(h.workspaceDir, "docs/a.txt"), 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3}, true)
	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	if r.Allowed || r.Stage != domain.StageExecute {
		t.Fatalf("%+v", r)
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 3 {
		t.Fatalf("call not refunded: %+v", rem)
	}
}

// TC-040-14: 예산 토큰 읽기 성공은 execute, settle 로 끝나고 완료 감사의 단계는 settle 이다.
func TestConsumeAfterCheck_BudgetReadEndsWithSettle(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "hello")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3, MaxReadBytes: 100}, true)
	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	if !r.Allowed {
		t.Fatalf("%+v", r)
	}
	n := len(r.Passed)
	if n < 2 || r.Passed[n-2] != domain.StageExecute || r.Passed[n-1] != domain.StageSettle {
		t.Fatalf("passed = %v", r.Passed)
	}
	var last map[string]interface{}
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "pep.allow" && ev["trace_id"] != nil {
			if md, _ := ev["metadata"].(map[string]interface{}); md["stage"] == string(domain.StageSettle) {
				last = ev
			}
		}
	}
	if last == nil {
		t.Fatal("completion audit with stage settle not found")
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 2 || rem.MaxReadBytes != 95 {
		t.Fatalf("remaining = %+v", rem)
	}
}
