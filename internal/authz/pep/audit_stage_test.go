package pep_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/domain"
)

// TC-050-04: 거부 요청의 감사 stage 는 실패한 단계이고 Metadata 에는 stage 가 없다.
func TestAuditStage_DenyRecordsFailedStageAtTopLevel(t *testing.T) {
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	if err := os.Symlink(t.TempDir(), filepath.Join(h.workspaceDir, "link")); err != nil {
		t.Fatal(err)
	}
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "link/x.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:link/x.txt", time.Hour, 1)
	wantDeny(t, run(t, gw, writeReq(tok, "link/x.txt", []byte("x"))), domain.ExitPathViolation, domain.ReasonSymlinkEscape, domain.StageBoundary)

	var found bool
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] != "pep.deny" {
			continue
		}
		found = true
		if ev["stage"] != string(domain.StageBoundary) {
			t.Errorf("stage = %v, want boundary", ev["stage"])
		}
		if md, _ := ev["metadata"].(map[string]interface{}); md["stage"] != nil {
			t.Errorf("metadata must not carry stage: %v", md)
		}
	}
	if !found {
		t.Fatal("pep.deny audit missing")
	}
}

// 사전 감사 기록은 precommit_audit 단계다.
func TestAuditStage_PrecommitRecord(t *testing.T) {
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/p.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/p.txt", time.Hour, 1)
	run(t, gw, writeReq(tok, "docs/p.txt", []byte("x")))
	var stages []interface{}
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "pep.allow" {
			stages = append(stages, ev["stage"])
		}
	}
	if len(stages) != 2 || stages[0] != string(domain.StagePrecommitAudit) || stages[1] != string(domain.StageExecute) {
		t.Fatalf("pep.allow stages = %v, want [precommit_audit execute]", stages)
	}
}

// TC-050-09: 승인 소비 기록의 stage 는 approval 이다.
func TestAuditStage_ApprovalConsumed(t *testing.T) {
	h := setupTestHarness(t)
	gw := askPEP(t, h, true, nil, nil)
	approvalGrant(t, h, "worker-01", "docs/o.txt")
	tok := issueValidToken(t, h, "worker-01", "file:write:docs/o.txt", time.Hour, 1)
	r0 := run(t, gw, writeReq(tok, "docs/o.txt", []byte("x")))
	approve(t, h, "worker-01", "docs/o.txt", r0.TokenJTI, []byte("x"))
	if r := run(t, gw, writeReq(tok, "docs/o.txt", []byte("x"))); !r.Allowed {
		t.Fatalf("%+v", r)
	}
	for _, ev := range auditActions(t, h.auditFile) {
		if ev["action"] == "approval.consumed" {
			if ev["stage"] != string(domain.StageApproval) {
				t.Fatalf("stage = %v", ev["stage"])
			}
			return
		}
	}
	t.Fatal("approval.consumed audit missing")
}

// TC-040-08: 실행이 시작된 exec:run 은 이후 settle 이 실패해도 호출분을 환급하지 않는다.
func TestExecStartedIsNotRefunded(t *testing.T) {
	h := setupTestHarness(t)
	ledger, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "b.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	gw := toolPEP(t, h, toolOpts{ledger: ledger})
	createGrant(t, h, "worker-01", domain.ActionExecRun, "echo-safe")
	// 출력("a\n" 2바이트)이 읽기 바이트 예산(1)을 넘는다: 실행 뒤 settle 에서 실패한다.
	tok := budgetExecToken(t, h, ledger, domain.Budget{MaxCalls: 5, MaxWriteBytes: 10, MaxReadBytes: 1})
	r := run(t, gw, execReq(tok, "echo-safe", "a"))
	wantDeny(t, r, domain.ExitAuthzDenied, domain.ReasonBudgetExhausted, domain.StageSettle)
	rem := remainingOf(t, ledger, jtiOfToken(t, h, tok))
	if rem.MaxCalls != 4 || rem.MaxWriteBytes != 9 {
		t.Fatalf("remaining = %+v, want calls 4 / write bytes 9 (no refund)", rem)
	}
}

func jtiOfToken(t *testing.T, h *testHarness, tok string) string {
	t.Helper()
	_, c, err := h.verifier.InspectToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	return c.JWTID
}
