package pep

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/pipeline"
)

// diffAssembly 는 조립 목록을 domain.PEPStages() 와 대조해 다른 곳을 돌려준다. ID·순서·성격·조건부를 본다.
func diffAssembly(steps []pipeline.Step[Call], specs []domain.StageSpec) []string {
	if len(steps) != len(specs) {
		return []string{"length differs"}
	}
	var d []string
	for i, sp := range specs {
		st := steps[i]
		if st.ID != string(sp.ID) {
			d = append(d, "id@"+string(sp.ID))
		}
		if st.Kind != kindOf[sp.Kind] {
			d = append(d, "kind@"+string(sp.ID))
		}
		if (st.Applies != nil) != sp.Conditional {
			d = append(d, "conditional@"+string(sp.ID))
		}
	}
	return d
}

// 조립 목록과 domain 정의의 일치. 기대값은 domain.PEPStages()(ADR 0007 표)다.
func TestAssemblyMatchesDomainStages(t *testing.T) {
	if d := diffAssembly((&gateway{}).assemble(), domain.PEPStages()); len(d) != 0 {
		t.Errorf("assembly differs from domain.PEPStages(): %v", d)
	}
}

// TC-040-16: 성격·조건부를 하나 바꾼 변이를 일치 시험이 잡는다.
func TestAssemblyMutationDetected(t *testing.T) {
	steps := (&gateway{}).assemble()
	steps[3].Kind = pipeline.Consume // boundary
	if d := diffAssembly(steps, domain.PEPStages()); len(d) != 1 {
		t.Errorf("kind mutation: want 1 diff, got %v", d)
	}
	steps = (&gateway{}).assemble()
	steps[5].Applies = nil // approval
	if d := diffAssembly(steps, domain.PEPStages()); len(d) != 1 {
		t.Errorf("conditional mutation: want 1 diff, got %v", d)
	}
}

// TC-040-10: 소비를 검사 앞으로 옮기면 조립이 실패한다.
func TestAssemblyConsumeBeforeCheckRejected(t *testing.T) {
	steps := (&gateway{}).assemble()
	steps[3], steps[4] = steps[4], steps[3] // replay(소비)를 boundary(검사) 앞으로
	if _, err := pipeline.New(steps, nil); err == nil {
		t.Error("want assembly error")
	}
}

// TC-030-02: gateway.go 는 행동 상수를 참조하지 않는다. 행동 지식은 tool*.go 에만 있다.
func TestGatewayHasNoActionConstants(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "gateway.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "domain" && strings.HasPrefix(sel.Sel.Name, "Action") && sel.Sel.Name != "Action" {
			t.Errorf("gateway.go references domain.%s", sel.Sel.Name)
		}
		return true
	})
}

// TC-030-03: 네 행동의 BudgetPlan (지시서 3장 표를 직접 적음)
func TestToolBudgetPlans(t *testing.T) {
	want := map[domain.Action]BudgetPlan{
		domain.ActionFileWrite: {ChargeWriteBytes: true, RefundAfterStart: true},
		domain.ActionExecRun:   {ChargeWriteBytes: true, PostCharge: true, RefundAfterStart: false},
		domain.ActionFileRead:  {PostCharge: true, RefundAfterStart: true},
		domain.ActionNetFetch:  {PostCharge: true, RefundAfterStart: true},
	}
	if len(tools) != len(want) {
		t.Fatalf("registered tools = %d, want %d", len(tools), len(want))
	}
	for a, w := range want {
		tl, ok := toolFor(a)
		if !ok {
			t.Fatalf("no tool for %s", a)
		}
		if got := tl.BudgetPlan(&Call{}); got != w {
			t.Errorf("%s: BudgetPlan = %+v, want %+v", a, got, w)
		}
	}
}

// TC-030-04: 등록되지 않은 행동은 표에서 찾지 못한다 (Gate 0 가 INVALID_ARGUMENTS 로 거부).
func TestUnregisteredActionHasNoTool(t *testing.T) {
	for _, a := range []domain.Action{"net:post", "exec", ""} {
		if _, ok := toolFor(a); ok {
			t.Errorf("toolFor(%q) must be false", a)
		}
	}
}
