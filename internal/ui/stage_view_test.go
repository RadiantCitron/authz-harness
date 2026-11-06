package ui

import (
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

func obsResult(exit domain.ExitCode, reason domain.Reason, stage domain.Stage, o harness.AuditObservation) harness.ScenarioResult {
	return harness.ScenarioResult{Assertion: harness.AssertionResult{
		ExitCodeActual: exit, AuditActualReason: reason, AuditActualStage: stage, Observed: o,
	}}
}

func states(v StageView) map[domain.Stage]CellState {
	m := map[domain.Stage]CellState{}
	for _, c := range v.Cells {
		m[c.Stage] = c.State
	}
	return m
}

func hasSide(v StageView, s string) bool {
	for _, l := range v.Side {
		if strings.HasPrefix(l, s) {
			return true
		}
	}
	return false
}

// TC-070-01·11: 거부는 기록된 단계가 차단이고 뒤는 건너뜀, 승인 소비 기록이 없으면 approval 은 해당 없음.
func TestStageView_DenyAtAuthn(t *testing.T) {
	v := BuildStageView(obsResult(domain.ExitTokenInvalid, domain.ReasonTokenReplayDetected, domain.StageAuthn,
		harness.AuditObservation{Action: "pep.deny", SchemaVersion: 4}))
	m := states(v)
	if m[domain.StageInput] != CellPassed || m[domain.StageAuthn] != CellBlocked || m[domain.StageAuthz] != CellSkipped || m[domain.StageSettle] != CellSkipped {
		t.Fatalf("unexpected: %v", m)
	}
	v = BuildStageView(obsResult(domain.ExitAuthzDenied, domain.ReasonBudgetExhausted, domain.StageBudget,
		harness.AuditObservation{Action: "pep.deny", SchemaVersion: 4}))
	if states(v)[domain.StageApproval] != CellNA {
		t.Fatalf("approval must be N/A without consumed record: %v", states(v))
	}
}

// TC-070-09: 허용 + 종료 코드 15 는 기록된 단계까지 통과, 별도 줄 「감사 검증: 차단」.
func TestStageView_AllowWithAuditTamper(t *testing.T) {
	v := BuildStageView(obsResult(domain.ExitAuditFailure, domain.ReasonAuthorized, domain.StageExecute,
		harness.AuditObservation{Action: "pep.allow", SchemaVersion: 4}))
	m := states(v)
	if m[domain.StageExecute] != CellPassed || m[domain.StageSettle] != CellNA || !hasSide(v, "감사 검증: 차단") {
		t.Fatalf("unexpected: %v side=%v", m, v.Side)
	}
	for _, c := range v.Cells {
		if c.State == CellBlocked {
			t.Fatalf("PEP cell must not be blocked: %v", c)
		}
	}
}

// 예산 차감 칸은 budget.consumed 기록이 근거다(계획 015): 기록 있으면 통과, 없으면 해당 없음.
func TestStageView_BudgetEvidence(t *testing.T) {
	settled := states(BuildStageView(obsResult(domain.ExitSuccess, domain.ReasonAuthorized, domain.StageSettle,
		harness.AuditObservation{Action: "pep.allow", SchemaVersion: 4, BudgetConsumed: true})))
	if settled[domain.StageBudget] != CellPassed || settled[domain.StageSettle] != CellPassed {
		t.Fatalf("unexpected: %v", settled)
	}
	plain := states(BuildStageView(obsResult(domain.ExitSuccess, domain.ReasonAuthorized, domain.StageExecute,
		harness.AuditObservation{Action: "pep.allow", SchemaVersion: 4})))
	if plain[domain.StageBudget] != CellNA {
		t.Fatalf("unexpected: %v", plain)
	}
}

// TC-070-04·08·10: 발급·교환·사전 감사 실패·진입 전 거부.
func TestStageView_NonPEPRecords(t *testing.T) {
	cases := []struct {
		name  string
		res   harness.ScenarioResult
		state CellState
		side  string
	}{
		{"발급 거부", obsResult(domain.ExitTokenInvalid, domain.ReasonAuthnUnknownClient, harness.NoStageRecord, harness.AuditObservation{Action: "token.issue.deny"}), CellNotEnter, "토큰 발급: 차단"},
		{"교환 거부", obsResult(domain.ExitAuthzDenied, domain.ReasonDelegationScopeExceeded, domain.StageDownscope, harness.AuditObservation{Action: "token.exchange.deny"}), CellNotEnter, "토큰 교환: 축소 위임 판정 차단"},
		{"사전 감사 실패", obsResult(domain.ExitAuditFailure, "", harness.NoStageRecord, harness.AuditObservation{}), CellUnknown, "감사 기록: 실패"},
		{"자식 미기동", obsResult(domain.ExitBadInput, "", harness.NoStageRecord, harness.AuditObservation{}), CellNotEnter, "진입 전: 차단"},
		{"격리", obsResult(domain.ExitPathViolation, "", harness.NoStageRecord, harness.AuditObservation{Action: "agent.confined"}), CellNotEnter, "격리: 차단"},
		{"자원 한계", obsResult(domain.ExitResourceLimit, domain.ReasonResourceTimeout, harness.NoStageRecord, harness.AuditObservation{Action: "agent.limit_exceeded"}), CellNotEnter, "실행 감독: 차단"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := BuildStageView(tc.res)
			for _, c := range v.Cells {
				if c.State != tc.state {
					t.Fatalf("cell %s = %s, want %s", c.Label, c.State, tc.state)
				}
			}
			if !hasSide(v, tc.side) {
				t.Fatalf("side %v lacks %q", v.Side, tc.side)
			}
		})
	}
}

// TC-070-05: 모르는 단계, 읽기 실패, v3 이하 기록은 판단 불가.
func TestStageView_UnknownEvidence(t *testing.T) {
	for name, res := range map[string]harness.ScenarioResult{
		"모르는 단계":       obsResult(domain.ExitAuthzDenied, "", "weird", harness.AuditObservation{Action: "pep.deny", SchemaVersion: 4}),
		"읽기 실패":        obsResult(domain.ExitAuthzDenied, "", "", harness.AuditObservation{ReadFailed: true}),
		"모르는 교환 단계":    obsResult(domain.ExitAuthzDenied, "", "weird", harness.AuditObservation{Action: "token.exchange.deny", SchemaVersion: 4}),
		"v3 기록":        obsResult(domain.ExitAuthzDenied, "", domain.StageAuthz, harness.AuditObservation{Action: "pep.deny", SchemaVersion: 3}),
		"단계 없는 PEP 기록": obsResult(domain.ExitAuthzDenied, "", harness.NoStageRecord, harness.AuditObservation{Action: "pep.deny", SchemaVersion: 4}),
	} {
		for _, c := range BuildStageView(res).Cells {
			if c.State != CellUnknown {
				t.Fatalf("%s: cell %s = %s", name, c.Label, c.State)
			}
		}
	}
}

// 칸 목록은 정식 단계 목록에서 읽는다.
func TestStageView_CellsFollowPEPStages(t *testing.T) {
	v := BuildStageView(obsResult(domain.ExitSuccess, "", harness.NoStageRecord, harness.AuditObservation{}))
	specs := domain.PEPStages()
	if len(v.Cells) != len(specs) {
		t.Fatalf("cells=%d specs=%d", len(v.Cells), len(specs))
	}
	for i, sp := range specs {
		if v.Cells[i].Stage != sp.ID || v.Cells[i].Label != sp.Label {
			t.Fatalf("cell %d mismatch", i)
		}
	}
}
