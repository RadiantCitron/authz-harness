package harness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	stepRule   = regexp.MustCompile(`^[a-z][a-z_]*\.[a-z][a-z_:]*$`)    // <부품>.<동작> 소문자
	actionRule = regexp.MustCompile(`^[a-z][a-z_]*(\.[a-z][a-z_:]*)+$`) // <대상>.<동작…> 소문자, 점 구분
	// 변경 전 어휘. 다시 나타나면 규칙 위반이다(ADR 0009 5장, 지시서 050 부록).
	retiredActions = map[string]bool{
		"grant.create": true, "grant.revoke": true, "epoch.bump": true,
		"authn.verify": true, "harness.startup": true, "audit.recover": true,
	}
)

// TC-050-05: 감사 이벤트의 Step·Action 문자열 리터럴이 어휘 규칙을 지킨다.
// 비테스트 코드에서 `Step: "…"`, `x.Step = "…"`, `Action: "…"` 로 쓰인 리터럴만 본다(변수·표현식은 대상 아님).
func TestAuditVocabularyRules(t *testing.T) {
	root := getRepoRoot(t)
	check := func(path string, pos token.Pos, fset *token.FileSet, field, lit string) {
		where := path + ":" + strconv.Itoa(fset.Position(pos).Line)
		switch field {
		case "Step":
			if !stepRule.MatchString(lit) {
				t.Errorf("%s: Step %q violates <부품>.<동작> lowercase rule", where, lit)
			}
		case "Action":
			if retiredActions[lit] {
				t.Errorf("%s: Action %q is a retired vocabulary value", where, lit)
			}
			// 도구 행동(file:read 등)은 Action 에 쓰지 않는다.
			if strings.Contains(lit, ":") && !strings.HasPrefix(lit, "pep.") {
				t.Errorf("%s: Action %q looks like a tool action", where, lit)
			}
			if lit != "" && !actionRule.MatchString(lit) {
				t.Errorf("%s: Action %q violates lowercase dotted rule", where, lit)
			}
		}
	}
	for _, top := range []string{"internal", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// 카탈로그의 ExpectedAction 등은 필드 이름이 달라 대상이 아니다.
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatal(perr)
			}
			rel, _ := filepath.Rel(root, path)
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.KeyValueExpr:
					if id, ok := x.Key.(*ast.Ident); ok && (id.Name == "Step" || id.Name == "Action") {
						if bl, ok := x.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
							v, _ := strconv.Unquote(bl.Value)
							check(rel, bl.Pos(), fset, id.Name, v)
						}
					}
				case *ast.AssignStmt:
					for i, l := range x.Lhs {
						sel, ok := l.(*ast.SelectorExpr)
						if !ok || (sel.Sel.Name != "Step" && sel.Sel.Name != "Action") || i >= len(x.Rhs) {
							continue
						}
						if bl, ok := x.Rhs[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
							v, _ := strconv.Unquote(bl.Value)
							check(rel, bl.Pos(), fset, sel.Sel.Name, v)
						}
					}
				}
				return true
			})
			return nil
		})
	}
}

// 규칙 자체의 변이 시험: 옛 어휘를 규칙이 걸러낸다.
func TestAuditVocabularyRulesRejectOldValues(t *testing.T) {
	for _, s := range []string{"020-issue", "ORCHESTRATE_SPAWN", "030-boot"} {
		if stepRule.MatchString(s) {
			t.Errorf("stepRule accepts %q", s)
		}
	}
	for _, s := range []string{"token.issue", "orchestrator.spawn", "pep.file:read", "harness.boot"} {
		if !stepRule.MatchString(s) {
			t.Errorf("stepRule rejects %q", s)
		}
	}
}
