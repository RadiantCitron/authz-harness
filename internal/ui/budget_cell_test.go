package ui

import (
	"reflect"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

func withBudgetConsumed(t *testing.T, o harness.AuditObservation, v bool) harness.AuditObservation {
	t.Helper()
	f := reflect.ValueOf(&o).Elem().FieldByName("BudgetConsumed")
	if !f.IsValid() {
		t.Fatal("AuditObservation.BudgetConsumed 필드가 없음")
	}
	f.SetBool(v)
	return o
}

// 계획 015 2.3 / 3장 B2·B3: `예산 차감` 칸은 budget.consumed 기록이 근거다.
func TestStageView_BudgetCellFollowsConsumedRecord(t *testing.T) {
	base := harness.AuditObservation{Action: "pep.allow", SchemaVersion: 4}
	cases := []struct {
		name     string
		end      domain.Stage
		consumed bool
		budget   CellState
		settle   CellState
	}{
		{"B2 예산 토큰 쓰기(정산 없음)", domain.StageExecute, true, CellPassed, CellNA},
		{"B1 예산 토큰 정산까지", domain.StageSettle, true, CellPassed, CellPassed},
		{"B3 예산 토큰 아님", domain.StageExecute, false, CellNA, CellNA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := withBudgetConsumed(t, base, tc.consumed)
			m := states(BuildStageView(obsResult(domain.ExitSuccess, domain.ReasonAuthorized, tc.end, o)))
			if m[domain.StageBudget] != tc.budget || m[domain.StageSettle] != tc.settle {
				t.Fatalf("budget=%s settle=%s, want %s/%s", m[domain.StageBudget], m[domain.StageSettle], tc.budget, tc.settle)
			}
		})
	}
}

// v3 이하 기록은 단계가 없으므로 기존대로 전부 판단 불가(칸 규칙이 바뀌어도 유지).
func TestStageView_BudgetCellV3StaysUnknown(t *testing.T) {
	o := harness.AuditObservation{Action: "pep.allow", SchemaVersion: 3}
	m := states(BuildStageView(obsResult(domain.ExitSuccess, domain.ReasonAuthorized, domain.StageExecute, o)))
	if m[domain.StageBudget] != CellUnknown {
		t.Fatalf("v3 budget = %s, want unknown", m[domain.StageBudget])
	}
}
