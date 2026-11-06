package harness

import (
	"testing"

	"authz-harness/internal/audit"
)

// 계획 015 B9(관측 층): 같은 TraceID 의 budget.consumed 유무를 AuditObservation 이 읽고,
// budget.consumed 가 있어도 매칭한 기록(마지막 pep.*)은 바뀌지 않는다.
func TestObserveAudit_BudgetConsumed(t *testing.T) {
	allow := audit.Event{TraceID: "t1", Action: "pep.allow", SchemaVersion: 4}
	consumed := audit.Event{TraceID: "t1", Action: "budget.consumed", SchemaVersion: 4}
	other := audit.Event{TraceID: "t2", Action: "budget.consumed", SchemaVersion: 4}

	cases := []struct {
		name   string
		events []audit.Event
		want   bool
	}{
		{"같은 요청에 기록 있음", []audit.Event{consumed, allow}, true},
		{"기록 없음", []audit.Event{allow}, false},
		{"다른 요청의 기록은 무시", []audit.Event{other, allow}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := allow
			o := observeAudit(tc.events, &m)
			if o.Action != "pep.allow" {
				t.Fatalf("매칭 기록이 바뀜: %q", o.Action)
			}
			if got := o.BudgetConsumed; got != tc.want {
				t.Fatalf("BudgetConsumed = %v, want %v", got, tc.want)
			}
		})
	}
}
