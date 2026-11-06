package pep

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

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
		domain.ActionFileWrite: {PreCharge: true, RefundAfterStart: true},
		domain.ActionExecRun:   {PreCharge: true, PostCharge: true, RefundAfterStart: false},
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
