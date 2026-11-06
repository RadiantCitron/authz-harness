package pep_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// windowGW 는 StageObserver 를 가진 예산 지원 PEP 를 만든다.
func windowGW(t *testing.T, h *testHarness, obs func(pep.Stage)) (pep.Gateway, *budget.FileLedger) {
	t.Helper()
	ledger, err := budget.NewFileLedger(filepath.Join(t.TempDir(), "budget_ledger.json"), domain.RealClock{})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := pep.NewGateway(pep.Config{Verifier: h.verifier, PDP: h.pdpSvc, Jail: h.jailInst,
		AuditWriter: h.auditWriter, BudgetLedger: ledger, StageObserver: obs})
	if err != nil {
		t.Fatal(err)
	}
	return gw, ledger
}

func chainToken(t *testing.T, h *testHarness) string {
	t.Helper()
	res, err := h.tokenIssuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "worker-01", Audience: "authz-harness", Scope: "file:read:docs/a.txt", TTL: time.Hour, Epoch: 1,
		DelegationDepth: 2,
		Actor: &domain.ActorClaim{Subject: "mid-01", Epoch: 1,
			Actor: &domain.ActorClaim{Subject: "lead-01", Epoch: 1}},
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "t", Actor: "t"})
	if err != nil {
		t.Fatalf("chain token: %v", err)
	}
	return res.TokenString
}

// TC-040-01, 02: 계보 연쇄 회수 (PIP→PDP 실경로)
func TestLineageRevocation(t *testing.T) {
	for _, victim := range []string{"lead-01", "mid-01"} {
		t.Run(victim+" Epoch 증가 시 worker-01 토큰 거부", func(t *testing.T) {
			h := setupTestHarness(t)
			createGrant(t, h, "worker-01", domain.ActionFileRead, "docs/a.txt")
			writeFixture(t, h, "docs/a.txt", "x")
			tok := chainToken(t, h)
			if _, err := h.papSvc.BumpEpoch(context.Background(), victim); err != nil {
				t.Fatal(err)
			}
			r := exec(t, h.gateway, tok, domain.ActionFileRead, "docs/a.txt", nil, false)
			if r.ExitCode != domain.ExitAuthzDenied || r.Reason != domain.ReasonSubjectEpochRevoked {
				t.Fatalf("got %d/%s", r.ExitCode, r.Reason)
			}
			if !strings.Contains(r.Details, victim) {
				t.Errorf("details %q lacks %s", r.Details, victim)
			}
		})
	}
	t.Run("조상 변경 없으면 통과(회귀 없음)", func(t *testing.T) {
		h := setupTestHarness(t)
		createGrant(t, h, "worker-01", domain.ActionFileRead, "docs/a.txt")
		writeFixture(t, h, "docs/a.txt", "x")
		if r := exec(t, h.gateway, chainToken(t, h), domain.ActionFileRead, "docs/a.txt", nil, false); r.ExitCode != 0 {
			t.Fatalf("got %d/%s", r.ExitCode, r.Reason)
		}
	})
}

// TC-040-06, 07, 08: TOCTOU Window A/B/C
func TestTOCTOUWindow(t *testing.T) {
	ctx := context.Background()
	type inj struct {
		name string
		do   func(t *testing.T, h *testHarness, gid string)
	}
	injections := []inj{
		{"Grant 회수", func(t *testing.T, h *testHarness, gid string) {
			if _, err := h.papSvc.RevokeGrant(ctx, gid); err != nil {
				t.Fatal(err)
			}
		}},
		{"주체 Epoch 증가", func(t *testing.T, h *testHarness, gid string) {
			if _, err := h.papSvc.BumpEpoch(ctx, "worker-01"); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, in := range injections {
		// Window A: Execute 진입 전 — 회수/Epoch 증가가 끝난 뒤 관문을 부른다
		t.Run("Window A/"+in.name, func(t *testing.T) {
			h := setupTestHarness(t)
			gw, ledger := windowGW(t, h, nil)
			gid := createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/out.txt")
			tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5}, true)
			in.do(t, h, gid)
			r, err := gw.Execute(ctx, pep.Request{Token: tok.TokenString, Action: domain.ActionFileWrite,
				Resource: "docs/out.txt", Data: []byte("new")})
			if err != nil {
				t.Fatal(err)
			}
			if r.ExitCode != domain.ExitAuthzDenied {
				t.Fatalf("exit = %d (%s)", r.ExitCode, r.Reason)
			}
			if _, statErr := os.Stat(filepath.Join(h.workspaceDir, "docs/out.txt")); statErr == nil {
				t.Error("file must not be written")
			}
		})

		// Window B: Gate 1 통과 직후
		t.Run("Window B/"+in.name, func(t *testing.T) {
			h := setupTestHarness(t)
			var gid string
			fired := false
			var tokVal string
			gw, ledger := windowGW(t, h, func(s pep.Stage) {
				if s == pep.StageGate1AuthN && !fired {
					fired = true
					in.do(t, h, gid)
				}
			})
			gid = createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/out.txt")
			tokVal = issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5}, true).TokenString
			r := exec(t, gw, tokVal, domain.ActionFileWrite, "docs/out.txt", []byte("new"), false)
			if !fired || r.ExitCode != domain.ExitAuthzDenied {
				t.Fatalf("fired=%v exit=%d (%s)", fired, r.ExitCode, r.Reason)
			}
			if _, statErr := os.Stat(filepath.Join(h.workspaceDir, "docs/out.txt")); statErr == nil {
				t.Error("file must not be written")
			}
		})
	}

	// Window C: Gate 2 통과 직후 — 진행 중 호출은 완료, 다음 호출은 거부
	t.Run("Window C/Grant 회수", func(t *testing.T) {
		h := setupTestHarness(t)
		var gid string
		fired := false
		var stages []pep.Stage
		record := true
		gw, ledger := windowGW(t, h, func(s pep.Stage) {
			if record {
				stages = append(stages, s)
			}
			if s == pep.StageGate2AuthZ && !fired {
				fired = true
				if _, err := h.papSvc.RevokeGrant(ctx, gid); err != nil {
					t.Fatal(err)
				}
			}
		})
		gid = createGrant(t, h, "worker-01", domain.ActionFileWrite, "docs/out.txt")
		tok := issueBudgetToken(t, h, ledger, domain.Budget{MaxCalls: 5}, true).TokenString

		r1 := exec(t, gw, tok, domain.ActionFileWrite, "docs/out.txt", []byte("one"), false)
		if r1.ExitCode != domain.ExitSuccess {
			t.Fatalf("1차 = %d (%s)", r1.ExitCode, r1.Reason)
		}
		if b, _ := os.ReadFile(filepath.Join(h.workspaceDir, "docs/out.txt")); string(b) != "one" {
			t.Errorf("file = %q", b)
		}
		// TC-040-08: 통과한 단계만 순서대로
		// 정식 순서(pep.Stages)에서 이 요청에 해당 없는 승인 단계만 뺀 것이다 (순서를 여기서 다시 적지 않는다).
		var want []pep.Stage
		for _, s := range pep.Stages() {
			if s != pep.StageApproval {
				want = append(want, s)
			}
		}
		if !reflect.DeepEqual(stages, want) {
			t.Errorf("stages = %v, want %v", stages, want)
		}

		stages = nil
		r2 := exec(t, gw, tok, domain.ActionFileWrite, "docs/out.txt", []byte("two"), false)
		if r2.ExitCode != domain.ExitAuthzDenied || r2.Reason != domain.ReasonGrantRevoked {
			t.Fatalf("2차 = %d/%s", r2.ExitCode, r2.Reason)
		}
		// 실패 단계(Gate 2)는 기록 없음
		if !reflect.DeepEqual(stages, []pep.Stage{pep.StageGate0Input, pep.StageGate1AuthN}) {
			t.Errorf("failed-call stages = %v", stages)
		}
	})
}
