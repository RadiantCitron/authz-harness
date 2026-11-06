package harness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// exchangeConstructionAllowed 는 exchange.NewExchangeService 를 직접 호출해도 되는 디렉터리(레포 루트 기준)다.
// 교환 서비스의 옵션(예산 원장·PIP 스냅샷)은 합성 루트 한 곳에서만 주입한다.
var exchangeConstructionAllowed = []string{
	filepath.Join("internal", "app"),
	filepath.Join("internal", "authn", "exchange"),
}

// findExchangeConstruction 은 파일(경로→AST)에서 exchange.NewExchangeService 호출을 찾는다.
func findExchangeConstruction(files map[string]*ast.File) []string {
	var out []string
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "exchange" && sel.Sel.Name == "NewExchangeService" {
				out = append(out, name+": direct call exchange.NewExchangeService")
			}
			return true
		})
	}
	return out
}

// 계획 020 W1 (TC-170-08): 교환 서비스는 합성 루트(app)와 exchange 패키지 밖에서 직접 조립하지 않는다.
// 기존 TC-170-02 는 internal/cli 만 보아 orchestrator·catalog 의 수동 조립을 놓쳤다.
func TestArchitecture_ExchangeServiceSingleConstruction(t *testing.T) {
	root := getRepoRoot(t)

	t.Run("internal 전체에서 합성 루트 밖 직접 호출 0건", func(t *testing.T) {
		files := map[string]*ast.File{}
		fset := token.NewFileSet()
		internalDir := filepath.Join(root, "internal")
		err := filepath.WalkDir(internalDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			for _, allowed := range exchangeConstructionAllowed {
				if strings.HasPrefix(rel, allowed+string(filepath.Separator)) {
					return nil
				}
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			files[rel] = f
			return nil
		})
		if err != nil {
			t.Fatalf("walk internal: %v", err)
		}
		if len(files) == 0 {
			t.Fatal("no source files scanned")
		}
		for _, v := range findExchangeConstruction(files) {
			t.Errorf("TC-170-08 violation: %s", v)
		}
	})

	t.Run("변이 검출: 위반을 주입하면 반드시 잡는다", func(t *testing.T) {
		bad, err := parser.ParseFile(token.NewFileSet(), "multi_hop.go",
			"package orchestrator\nfunc f() { _ = exchange.NewExchangeService(nil, nil, nil, nil, nil, nil) }\n", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := findExchangeConstruction(map[string]*ast.File{"multi_hop.go": bad}); len(got) != 1 {
			t.Errorf("guard failed to detect injected call: %v", got)
		}
		ok, _ := parser.ParseFile(token.NewFileSet(), "x.go", "package p\nfunc g() {}\n", 0)
		if got := findExchangeConstruction(map[string]*ast.File{"x.go": ok}); len(got) != 0 {
			t.Errorf("guard false positive: %v", got)
		}
	})
}
