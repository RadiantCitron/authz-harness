package pep_test

import (
	"authz-harness/internal/audit"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// 계획 015 인수 시험 (B1, B3, B4, B5, B6, B9 의 PEP 층).
// 시나리오는 계획 015 3장에서 도출했다. 구현을 읽고 베낀 것이 아니다.

// failOnActionWriter 는 지정한 Action 의 기록만 실패시키고 나머지는 실제 기록기로 넘긴다.
type failOnActionWriter struct {
	domain.AuditWriter
	action string
}

func (w failOnActionWriter) Log(ev domain.AuditEvent) error {
	if ev.Action == w.action {
		return errors.New("injected audit failure for " + w.action)
	}
	return w.AuditWriter.Log(ev)
}

func budgetConsumedRecords(t *testing.T, h *testHarness) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "budget.consumed" {
			out = append(out, ev)
		}
	}
	return out
}

func indexOfAction(t *testing.T, h *testHarness, action string) int {
	t.Helper()
	for i, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == action {
			return i
		}
	}
	return -1
}

// B1: 예산 토큰으로 file:read 허용 → budget.consumed 정확히 1건, pep.allow 보다 앞.
func TestBudgetConsumed_B1_ReadAllowRecordsOnce(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "hello")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3}, true)

	if r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false); !r.Allowed {
		t.Fatalf("read: %+v", r)
	}
	recs := budgetConsumedRecords(t, h)
	if len(recs) != 1 {
		t.Fatalf("budget.consumed = %d건, want 1", len(recs))
	}
	ev := recs[0]
	if ev["stage"] != string(domain.StageBudget) || ev["token_jti"] != tok.Claims.JWTID || ev["success"] != true {
		t.Errorf("record = %v", ev)
	}
	if bi, ai := indexOfAction(t, h, "budget.consumed"), indexOfAction(t, h, "pep.allow"); bi < 0 || ai < 0 || bi > ai {
		t.Errorf("budget.consumed(%d) must precede pep.allow(%d)", bi, ai)
	}
}

// B1(쓰기): 예산 토큰으로 file:write 허용도 1건.
func TestBudgetConsumed_B1_WriteAllowRecordsOnce(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3, MaxWriteBytes: 10}, true)

	if r := exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", []byte("abc"), false); !r.Allowed {
		t.Fatalf("write: %+v", r)
	}
	if n := len(budgetConsumedRecords(t, h)); n != 1 {
		t.Fatalf("budget.consumed = %d건, want 1", n)
	}
}

// B3(PEP 층): 예산 토큰이 아닌 허용 요청은 budget.consumed 를 남기지 않는다.
func TestBudgetConsumed_B3_NonBudgetTokenRecordsNothing(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "x")
	gw, _ := budgetPEP(t, h, true)
	tok := issueValidToken(t, h, "worker-01", "file:read:docs/a.txt", time.Hour, 1)

	if r := exec(t, gw, tok, domain.ActionFileRead, "docs/a.txt", nil, false); !r.Allowed {
		t.Fatalf("read: %+v", r)
	}
	if n := len(budgetConsumedRecords(t, h)); n != 0 {
		t.Fatalf("budget.consumed = %d건, want 0", n)
	}
}

// B4: 예산 소진으로 budget 단계에서 거부 → budget.consumed 없음.
func TestBudgetConsumed_B4_ExhaustedRecordsNothing(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "x")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 1}, true)

	if r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false); !r.Allowed {
		t.Fatalf("1st: %+v", r)
	}
	r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	if r.Reason != domain.ReasonBudgetExhausted || r.Stage != domain.StageBudget {
		t.Fatalf("2nd: reason=%s stage=%s", r.Reason, r.Stage)
	}
	if n := len(budgetConsumedRecords(t, h)); n != 1 { // 첫 요청의 1건만
		t.Fatalf("budget.consumed = %d건, want 1 (거부된 요청은 기록 없음)", n)
	}
}

// B5: budget.consumed 기록만 실패 → 종료 코드 15, 실행 안 됨, 장부 환급.
func TestBudgetConsumed_B5_RecordFailureRefundsAndDenies(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	ledger, err := budget.NewFileLedger(t.TempDir()+"/budget_ledger.json", domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := pep.NewGateway(pep.Config{
		Verifier: h.verifier, PDP: h.pdpSvc, Jail: h.jailInst, BudgetLedger: ledger,
		AuditWriter: failOnActionWriter{AuditWriter: h.auditWriter, action: "budget.consumed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5, MaxWriteBytes: 10}, true)

	r := exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", []byte("abcde"), false)
	if r.Allowed || r.ExitCode != domain.ExitAuditFailure || r.Reason != domain.ReasonAuditLogFailed {
		t.Fatalf("got exit=%d reason=%s allowed=%v, want 15/AUDIT_LOG_FAILED", r.ExitCode, r.Reason, r.Allowed)
	}
	if fileExists(h, "docs/out.txt") {
		t.Fatal("작업이 실행되면 안 된다")
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 5 || rem.MaxWriteBytes != 10 {
		t.Fatalf("환급 안 됨: %+v", rem)
	}
}

// B6: budget 뒤 단계(precommit_audit 주입 실패)에서 거부 → 장부 원복. 기록은 「그 시점 차감」으로 남는다.
func TestBudgetConsumed_B6_LaterStageFailureRefunds(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5, MaxWriteBytes: 10}, true)

	r := exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", []byte("abcde"), true)
	if r.Allowed || r.Reason != domain.ReasonAuditLogFailed {
		t.Fatalf("got %+v", r)
	}
	if rem := remainingOf(t, ledger, tok.Claims.JWTID); rem.MaxCalls != 5 || rem.MaxWriteBytes != 10 {
		t.Fatalf("not refunded: %+v", rem)
	}
}

// B9(PEP 층): budget.consumed 가 있어도 같은 요청의 pep.allow/pep.deny 순서는 budget.consumed 가 그 앞에 온다.
func TestBudgetConsumed_B9_PepDecisionRemainsLast(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "0123456789")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3, MaxReadBytes: 2}, true) // 읽기 바이트 초과 → deny

	if r := exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false); r.Allowed {
		t.Fatalf("want deny: %+v", r)
	}
	evs := auditActions(t, h.auditFile)
	last := ""
	for _, ev := range evs {
		if a, _ := ev["action"].(string); a == "pep.allow" || a == "pep.deny" || a == "budget.consumed" {
			last = a
		}
	}
	if last != "pep.deny" {
		t.Fatalf("마지막 판정 계열 기록 = %q, want pep.deny", last)
	}
}

// B7: budget.consumed 가 섞인 감사 파일도 해시 사슬이 통과하고 원시 토큰은 기록에 없다.
func TestBudgetConsumed_B7_ChainVerifiesAndNoRawToken(t *testing.T) {
	h := setupTestHarness(t)
	grantAll(t, h)
	writeFixture(t, h, "docs/a.txt", "x")
	gw, ledger := budgetPEP(t, h, true)
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 3, MaxWriteBytes: 10}, true)

	exec(t, gw, tok.TokenString, domain.ActionFileRead, "docs/a.txt", nil, false)
	exec(t, gw, tok.TokenString, domain.ActionFileWrite, "docs/out.txt", []byte("ab"), false)
	if n := len(budgetConsumedRecords(t, h)); n != 2 {
		t.Fatalf("budget.consumed = %d건, want 2", n)
	}
	if err := audit.VerifyHashChain(h.auditFile); err != nil {
		t.Fatalf("hash chain: %v", err)
	}
	raw, err := os.ReadFile(h.auditFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), tok.TokenString) {
		t.Fatal("원시 토큰이 감사 파일에 노출됨")
	}
}
