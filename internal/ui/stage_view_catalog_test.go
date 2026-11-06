package ui_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/harness/catalog"
	"authz-harness/internal/ui"
)

// TC-070-02·03: 실제 79건을 돌려 화면과 감사 기록을 대조한다.
// 종료 코드가 0이 아닌 시나리오는 차단·실패·판단 불가가 하나 이상 보여야 하고, 막힌 칸은 기록된 단계와 같아야 한다.
func TestStageView_AllScenarios(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	t.Cleanup(func() { _ = runner.Close() })
	if err := catalog.RegisterAll(runner); err != nil {
		t.Fatal(err)
	}
	results, err := runner.RunAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Skipped {
			continue
		}
		v := ui.BuildStageView(r)
		id := r.Metadata.ID
		if r.Assertion.ExitCodeActual != domain.ExitSuccess {
			shown := len(v.Side) > 0
			for _, c := range v.Cells {
				if c.State == ui.CellBlocked || c.State == ui.CellUnknown {
					shown = true
				}
			}
			if !shown {
				t.Errorf("%s: 종료 코드 %d 인데 차단·실패·판단 불가가 없다", id, r.Assertion.ExitCodeActual)
			}
		}
		if b := v.Blocked(); b != nil && b.Stage != r.Assertion.AuditActualStage {
			t.Errorf("%s: 화면 차단 %s != 감사 기록 %s", id, b.Stage, r.Assertion.AuditActualStage)
		}
		if r.Metadata.Expected.ExitCode == domain.ExitAuditFailure || r.Metadata.Expected.ExitCode != domain.ExitSuccess {
			allPassed := true
			for _, c := range v.Cells {
				if c.State != ui.CellPassed {
					allPassed = false
				}
			}
			if allPassed {
				t.Errorf("%s: 실패 시나리오가 전 칸 통과로 그려졌다", id)
			}
		}
		out := ui.RenderScenarioExplain(r)
		if strings.Contains(out, "Gate ") || strings.Contains(out, "6대 관문") {
			t.Errorf("%s: 설명 화면에 옛 관문 표현이 남아 있다", id)
		}
	}
}

// TC-070-07: ui/pipeline.go 는 시나리오 ID·그룹으로 분기하지 않는다.
func TestPipelineGo_NoScenarioBranching(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "pipeline.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && (s.Sel.Name == "ID" || s.Sel.Name == "Group") {
			if x, ok := s.X.(*ast.SelectorExpr); ok && x.Sel.Name == "Metadata" {
				t.Errorf("pipeline.go 가 %s.%s 를 읽는다", x.Sel.Name, s.Sel.Name)
			}
		}
		if l, ok := n.(*ast.BasicLit); ok && strings.HasPrefix(l.Value, `"E2E-`) {
			t.Errorf("pipeline.go 에 시나리오 ID 리터럴 %s", l.Value)
		}
		return true
	})
}
