package pep_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// 계획 013 S1: 단계의 정식 순서(domain.PEPStages)와 요청별 통과 기록(Result.Passed)을 고정한다.
// 단계를 runPipeline 에 끼우고 Stages 에 넣지 않으면 아래 시험이 실패해, 화면이 순서표를 따로 들다가
// 새 단계를 빠뜨린 결함(보고서 034)과 같은 실수를 시험이 잡는다.

// orderGW 는 승인 소비기·예산 원장·StageObserver 를 모두 가진 관문을 만든다.
func orderGW(t *testing.T, h *testHarness, obs func(domain.Stage)) (pep.Gateway, *budget.FileLedger) {
	t.Helper()
	ledger, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "budget_ledger.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := pep.NewGateway(pep.Config{Verifier: h.verifier, PDP: h.pdpSvc, Jail: h.jailInst,
		AuditWriter: h.auditWriter, BudgetLedger: ledger,
		ApprovalConsumer: state.NewApprovalConsumer(h.store), StageObserver: obs})
	if err != nil {
		t.Fatal(err)
	}
	return gw, ledger
}

func stageIndex(s domain.Stage) int {
	for i, c := range domain.PEPStages() {
		if c.ID == s {
			return i
		}
	}
	return -1
}

// assertPassedConsistent 는 모든 결과가 지켜야 하는 불변식이다: Passed 는 정식 순서를 따르는 부분 수열이고,
// 거부면 실패 단계는 Passed 에 없으며 Passed 의 모든 단계는 실패 단계보다 앞선다.
func assertPassedConsistent(t *testing.T, r *pep.Result) {
	t.Helper()
	prev := -1
	for _, s := range r.Passed {
		i := stageIndex(s)
		if i < 0 {
			t.Fatalf("Passed has stage %q that is not in domain.PEPStages() — add it to stageOrder", s)
		}
		if i <= prev {
			t.Fatalf("Passed is not in canonical order: %v", r.Passed)
		}
		prev = i
	}
	if r.Allowed {
		return
	}
	fi := stageIndex(r.Stage)
	if fi < 0 {
		t.Fatalf("failed stage %q is not in domain.PEPStages()", r.Stage)
	}
	for _, s := range r.Passed {
		if s == r.Stage {
			t.Fatalf("failed stage %q must not be in Passed: %v", r.Stage, r.Passed)
		}
		if stageIndex(s) >= fi {
			t.Fatalf("Passed stage %q is not before failed stage %q", s, r.Stage)
		}
	}
}

// P4: Stages 가 돌려준 슬라이스를 고쳐도 내부 목록은 바뀌지 않는다.
func TestStages_ReturnsCopy(t *testing.T) {
	a := domain.PEPStages()
	if len(a) != 10 {
		t.Fatalf("len = %d, want 10", len(a))
	}
	first := a[0]
	a[0].ID = "tampered"
	if b := domain.PEPStages(); b[0] != first {
		t.Fatalf("internal order was modified: %v", b)
	}
}

// P1·P3: 승인+예산 쓰기 허가는 settle 을 뺀 9단계를 모두 통과하고, Passed 는 독립 장치(StageObserver)가 본 순서와 같다.
func TestStageOrder_FullPathPassesEveryStage(t *testing.T) {
	h := setupTestHarness(t)
	var observed []domain.Stage
	record := false
	gw, ledger := orderGW(t, h, func(s domain.Stage) {
		if record {
			observed = append(observed, s)
		}
	})
	approvalGrant(t, h, "worker-01", "docs/out.txt")
	tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5}, true)
	data := []byte("x")

	r0, err := gw.Execute(context.Background(), writeReq(tok.TokenString, "docs/out.txt", data))
	if err != nil {
		t.Fatal(err)
	}
	if r0.ExitCode != domain.ExitApprovalRequired {
		t.Fatalf("ask: %+v", r0)
	}
	assertPassedConsistent(t, r0)
	approve(t, h, "worker-01", "docs/out.txt", r0.TokenJTI, data)

	record = true
	r, err := gw.Execute(context.Background(), writeReq(tok.TokenString, "docs/out.txt", data))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Fatalf("expected allow: %+v", r)
	}
	assertPassedConsistent(t, r)
	// 쓰기는 사후 정산이 없으므로 settle 만 빠진다.
	var want []domain.Stage
	for _, sp := range domain.PEPStages() {
		if sp.ID != domain.StageSettle {
			want = append(want, sp.ID)
		}
	}
	if !reflect.DeepEqual(r.Passed, want) {
		t.Errorf("Passed = %v, want every stage but settle %v", r.Passed, want)
	}
	if !reflect.DeepEqual(r.Passed, observed) {
		t.Errorf("Passed = %v, StageObserver saw %v", r.Passed, observed)
	}
}

// 조건부 단계(승인·예산)가 해당 없는 허가 요청은 그 두 단계만 빠진다.
func TestStageOrder_ConditionalStagesOmittedWhenNotApplicable(t *testing.T) {
	h := setupTestHarness(t)
	var observed []domain.Stage
	gw, _ := orderGW(t, h, func(s domain.Stage) { observed = append(observed, s) })
	createGrant(t, h, "worker-01", domain.ActionFileRead, "docs/a.txt")
	writeFixture(t, h, "docs/a.txt", "hello")
	tok := issueValidToken(t, h, "worker-01", "file:read:docs/a.txt", time.Hour, 1)

	r, err := gw.Execute(context.Background(), pep.Request{Token: tok, Action: domain.ActionFileRead, Resource: "docs/a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Fatalf("expected allow: %+v", r)
	}
	assertPassedConsistent(t, r)
	want := []domain.Stage{domain.StageInput, domain.StageAuthn, domain.StageAuthz, domain.StageBoundary,
		domain.StageReplay, domain.StagePrecommitAudit, domain.StageExecute}
	if !reflect.DeepEqual(r.Passed, want) {
		t.Errorf("Passed = %v, want %v", r.Passed, want)
	}
	if !reflect.DeepEqual(r.Passed, observed) {
		t.Errorf("Passed = %v, StageObserver saw %v", r.Passed, observed)
	}
}

// P2: 여러 단계에서 거부된 결과가 모두 불변식을 지키고, 기대한 지점까지만 통과 기록이 있다.
func TestStageOrder_FailurePathsKeepInvariant(t *testing.T) {
	h := setupTestHarness(t)
	gw, ledger := orderGW(t, h, nil)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(h.workspaceDir, "link")); err != nil {
		t.Fatal(err)
	}
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "link/x.txt")
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/out.txt")
	createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/b.txt")

	jailTok := issueValidToken(t, h, "worker-01", "file:write:link/x.txt", time.Hour, 1)
	auditTok := issueValidToken(t, h, "worker-01", "file:write:docs/out.txt", time.Hour, 1)
	noGrantTok := issueValidToken(t, h, "worker-01", "file:write:docs/nogrant.txt", time.Hour, 1)
	budgetTok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5, MaxWriteBytes: 1}, true)

	tests := []struct {
		name      string
		req       pep.Request
		wantStage domain.Stage
		wantPass  []domain.Stage
	}{
		{"input 단계 빈 대상", pep.Request{Token: "x", Action: domain.ActionFileRead, Resource: ""},
			domain.StageInput, nil},
		{"authn 단계 잘못된 토큰", pep.Request{Token: "invalid.jwt.token", Action: domain.ActionFileRead, Resource: "docs/a.txt"},
			domain.StageAuthn, []domain.Stage{domain.StageInput}},
		{"authz 단계 권한 없음", writeReq(noGrantTok, "docs/nogrant.txt", []byte("x")),
			domain.StageAuthz, []domain.Stage{domain.StageInput, domain.StageAuthn}},
		{"boundary 단계 심볼릭 링크 탈출", writeReq(jailTok, "link/x.txt", []byte("x")),
			domain.StageBoundary, []domain.Stage{domain.StageInput, domain.StageAuthn, domain.StageAuthz}},
		{"Budget 쓰기 바이트 초과", writeReq(budgetTok.TokenString, "docs/out.txt", []byte("too-long")),
			domain.StageBudget, []domain.Stage{domain.StageInput, domain.StageAuthn, domain.StageAuthz, domain.StageBoundary, domain.StageReplay}},
		{"precommit_audit 단계 사전 감사 실패", pep.Request{Token: auditTok, Action: domain.ActionFileWrite, Resource: "docs/out.txt",
			Data: []byte("x"), InjectAuditFailure: true},
			domain.StagePrecommitAudit, []domain.Stage{domain.StageInput, domain.StageAuthn, domain.StageAuthz, domain.StageBoundary, domain.StageReplay}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := gw.Execute(context.Background(), tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed || r.Stage != tc.wantStage {
				t.Fatalf("stage = %q allowed=%v (%s), want deny at %q", r.Stage, r.Allowed, r.Reason, tc.wantStage)
			}
			assertPassedConsistent(t, r)
			if len(r.Passed) != len(tc.wantPass) || (len(tc.wantPass) > 0 && !reflect.DeepEqual(r.Passed, tc.wantPass)) {
				t.Errorf("Passed = %v, want %v", r.Passed, tc.wantPass)
			}
		})
	}
}
