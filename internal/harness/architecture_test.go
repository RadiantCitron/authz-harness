package harness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// getRepoRoot 는 runtime.Caller(0)을 기준으로 상위로 거슬러 올라가 go.mod가 있는 최상위 레포지토리 루트 절대경로를 반환한다.
func getRepoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get caller info from runtime")
	}
	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("failed to locate repo root containing go.mod")
		}
		dir = parent
	}
}

// TestArchitectureGuardrails 는 07번 로드맵의 12대 안티패턴 재발을 영구 방지하는
// 아키텍처 적합성 함수(Architecture Fitness Functions)다.
func TestArchitectureGuardrails(t *testing.T) {
	root := getRepoRoot(t)

	// TC-060-01: PDP의 파일/OS 의존성 0%
	t.Run("TC-060-01: PDP 패키지의 파일/OS/Jail 의존성 0% 검증", func(t *testing.T) {
		pdpDir := filepath.Join(root, "internal", "authz", "pdp")
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, pdpDir, func(fi fs.FileInfo) bool {
			// 테스트 파일은 제외하고 실제 비즈니스 코드만 검사
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed to parse pdp dir: %v", err)
		}

		prohibited := map[string]bool{
			`"os"`:                          true,
			`"path/filepath"`:               true,
			`"io/fs"`:                       true,
			`"authz-harness/internal/jail"`: true,
		}

		for _, pkg := range pkgs {
			for fname, file := range pkg.Files {
				for _, imp := range file.Imports {
					val := imp.Path.Value
					if prohibited[val] {
						t.Errorf("violation of AP-03 in %s: PDP must not import %s", fname, val)
					}
				}
			}
		}
	})

	// TC-060-02: Subagent의 중앙 상태 저장소 의존성 0%
	t.Run("TC-060-02: Subagent 패키지의 중앙 상태/PAP/키관리 의존성 0% 검증", func(t *testing.T) {
		subagentDir := filepath.Join(root, "internal", "subagent")
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, subagentDir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed to parse subagent dir: %v", err)
		}

		prohibited := map[string]bool{
			`"authz-harness/internal/authz/state"`: true,
			`"authz-harness/internal/authz/pap"`:   true,
			`"authz-harness/internal/authn/keys"`:  true,
		}

		for _, pkg := range pkgs {
			for fname, file := range pkg.Files {
				for _, imp := range file.Imports {
					val := imp.Path.Value
					if prohibited[val] {
						t.Errorf("violation of AP-06/AP-11 in %s: Subagent must not import %s", fname, val)
					}
				}
			}
		}
	})

	// TC-060-03: internal/ 전체 문자열 에러 파싱 0% (strings.Contains(err.Error(), ...))
	t.Run("TC-060-03: internal/ 전체 코드의 문자열 에러 파싱(strings.Contains) 0% 검증", func(t *testing.T) {
		internalDir := filepath.Join(root, "internal")
		fset := token.NewFileSet()

		var violations []string

		err := filepath.WalkDir(internalDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				// 테스트 코드가 아닌 프로덕션 코드 대상
				return nil
			}

			fileNode, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}

			ast.Inspect(fileNode, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				// strings.Contains(...) 호출 감지
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "strings" || sel.Sel.Name != "Contains" {
					return true
				}

				// 첫 번째 인자가 .Error() 호출인지 확인
				if len(call.Args) > 0 {
					if innerCall, ok := call.Args[0].(*ast.CallExpr); ok {
						if innerSel, ok := innerCall.Fun.(*ast.SelectorExpr); ok {
							if innerSel.Sel.Name == "Error" {
								pos := fset.Position(call.Pos())
								rel, _ := filepath.Rel(root, pos.Filename)
								violations = append(violations, rel+":"+pos.String())
							}
						}
					}
				}
				return true
			})

			return nil
		})

		if err != nil {
			t.Fatalf("failed to walk internal dir: %v", err)
		}

		if len(violations) > 0 {
			t.Fatalf("violation of AP-01: found %d strings.Contains(err.Error(), ...) occurrences:\n%s", len(violations), strings.Join(violations, "\n"))
		}
	})

	// TC-060-04: PEP Gateway.Execute 의 단일 출구(Single-Entry Single-Exit) 보장 검증
	t.Run("TC-060-04: PEP Gateway.Execute 함수의 단일 출구(SESE 1 return) 정적 구조 검증", func(t *testing.T) {
		pepFile := filepath.Join(root, "internal", "authz", "pep", "gateway.go")
		fset := token.NewFileSet()
		fileNode, err := parser.ParseFile(fset, pepFile, nil, 0)
		if err != nil {
			t.Fatalf("failed to parse gateway.go: %v", err)
		}

		var executeFn *ast.FuncDecl
		for _, decl := range fileNode.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Name.Name == "Execute" && fn.Recv != nil && len(fn.Recv.List) > 0 {
				executeFn = fn
				break
			}
		}

		if executeFn == nil {
			t.Fatal("failed to find (g *gateway) Execute declaration in gateway.go")
		}

		var returnStmts []*ast.ReturnStmt
		ast.Inspect(executeFn.Body, func(n ast.Node) bool {
			// 중첩 함수 리터럴(익명 함수)의 return은 제외
			if fnLit, ok := n.(*ast.FuncLit); ok {
				return fnLit == nil // 익명 함수 내부 탐색 방지
			}
			if ret, ok := n.(*ast.ReturnStmt); ok {
				returnStmts = append(returnStmts, ret)
			}
			return true
		})

		if len(returnStmts) != 1 {
			t.Fatalf("violation of SESE: (g *gateway) Execute must have exactly 1 return statement (finalize 단일 출구), found %d", len(returnStmts))
		}
	})
}
