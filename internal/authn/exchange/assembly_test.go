package exchange

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"authz-harness/internal/authn/budget"
	"authz-harness/internal/domain"
	"authz-harness/internal/pipeline"
)

type noSnaps struct{}

func (noSnaps) GetSubjectSnapshot(context.Context, string) (*domain.SubjectSnapshot, error) {
	return nil, nil
}

// TC-080 2층위: 조립 목록은 domain.ExchangeStages() 와 ID·순서·성격·조건부가 같다.
func TestAssembleMatchesExchangeStages(t *testing.T) {
	s := NewExchangeService(nil, nil, nil, nil, nil, nil, WithBudgetLedger(budget.Ledger(nil)), WithSnapshotProvider(noSnaps{}))
	if s.engineErr != nil {
		t.Fatal(s.engineErr)
	}
	steps := s.assemble()
	specs := domain.ExchangeStages()
	if len(steps) != len(specs) {
		t.Fatalf("steps=%d specs=%d", len(steps), len(specs))
	}
	for i, sp := range specs {
		st := steps[i]
		if st.ID != string(sp.ID) {
			t.Errorf("[%d] id %q != %q", i, st.ID, sp.ID)
		}
		if st.Kind != pipeline.Kind(sp.Kind) {
			t.Errorf("[%d] kind %q != %q", i, st.Kind, pipeline.Kind(sp.Kind))
		}
		if (st.Applies != nil) != sp.Conditional {
			t.Errorf("[%d] conditional %v != %v", i, st.Applies != nil, sp.Conditional)
		}
	}
}

// 조건부 단계는 스냅샷 공급자·예산 관여 여부에 따라 건너뛴다.
func TestConditionalStepsApply(t *testing.T) {
	bare := NewExchangeService(nil, nil, nil, nil, nil, nil)
	for _, st := range bare.assemble() {
		if st.ID == string(domain.StageLineageEpoch) && st.Applies(&exchangeCall{}) {
			t.Error("lineage_epoch must be skipped without a snapshot provider")
		}
		if st.ID == string(domain.StageBudgetReserve) {
			if st.Applies(&exchangeCall{}) || !st.Applies(&exchangeCall{budgetInvolved: true}) {
				t.Error("budget_reserve must follow budgetInvolved")
			}
		}
	}
}

// TC-080-08: budget_reserve 를 소비로 바꾼 변이는 조립이 거부된다(등급 하강).
func TestAssembleRejectsReserveAsConsume(t *testing.T) {
	s := NewExchangeService(nil, nil, nil, nil, nil, nil)
	steps := s.assemble()
	steps[len(steps)-1].Kind = pipeline.Consume
	if _, err := pipeline.New[exchangeCall](steps, nil); err == nil {
		t.Fatal("consume after execute must be rejected")
	}
}

// TC-080-04: recordAuditDenied 호출은 service.go 에서 마감 한 곳뿐이다.
func TestRecordAuditDeniedCalledOnce(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "service.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "recordAuditDenied" {
				n++
			}
		}
		return true
	})
	if n != 1 {
		t.Fatalf("recordAuditDenied calls = %d, want 1", n)
	}
}
