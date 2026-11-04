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

	// TC-080-01: Orchestrator 및 Control Plane 비즈니스 코드 내부의 _ = Audit.Log 무시 0건 검증
	t.Run("TC-080-01: Orchestrator 비즈니스 코드의 감사 에러 무시(_ = s.cfg.Audit.Log) 0건 검증", func(t *testing.T) {
		orchDir := filepath.Join(root, "internal", "orchestrator")
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, orchDir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ParseComments)
		if err != nil {
			t.Fatalf("failed to parse orchestrator dir: %v", err)
		}

		for _, pkg := range pkgs {
			for fname, file := range pkg.Files {
				ast.Inspect(file, func(n ast.Node) bool {
					assign, ok := n.(*ast.AssignStmt)
					if !ok {
						return true
					}
					// _ = ... 형태 검사
					if len(assign.Lhs) == 1 {
						if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name == "_" {
							for _, rhs := range assign.Rhs {
								if call, ok := rhs.(*ast.CallExpr); ok {
									if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Log" {
										t.Errorf("forbidden audit error ignoring '_ = ...Log' found in %s:%d", fname, fset.Position(assign.Pos()).Line)
									}
								}
							}
						}
					}
					return true
				})
			}
		}
	})

	// TC-090-01: MCP 패키지의 파일/OS/PDP/PIP/Jail/Keys 의존성 0% 검증
	t.Run("TC-090-01: MCP 어댑터 패키지의 파일/OS/PDP/PIP/Jail/Keys 의존성 0% 검증", func(t *testing.T) {
		mcpDir := filepath.Join(root, "internal", "mcp")
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, mcpDir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed to parse mcp dir: %v", err)
		}

		prohibited := map[string]bool{
			`"os"`:                                true,
			`"io/fs"`:                             true,
			`"path/filepath"`:                     true,
			`"authz-harness/internal/authz/pdp"`:  true,
			`"authz-harness/internal/authz/pip"`:  true,
			`"authz-harness/internal/jail"`:       true,
			`"authz-harness/internal/authn/keys"`: true,
		}

		for _, pkg := range pkgs {
			for fname, file := range pkg.Files {
				for _, imp := range file.Imports {
					val := imp.Path.Value
					if prohibited[val] {
						t.Errorf("violation of TC-090-01 in %s: internal/mcp must not import %s", fname, val)
					}
				}
			}
		}
	})

	// TC-081-01: internal/authn 및 internal/authz/state 내 직접 syscall.Flock 호출 0건 검증 (storage.AtomicFileStore 일원화)
	t.Run("TC-081-01: authn 및 authz/state 내 직접 syscall.Flock 호출 금지 (storage 일원화)", func(t *testing.T) {
		dirsToCheck := []string{
			filepath.Join(root, "internal", "authn"),
			filepath.Join(root, "internal", "authz", "state"),
		}

		fset := token.NewFileSet()
		for _, dir := range dirsToCheck {
			err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}

				node, err := parser.ParseFile(fset, path, nil, 0)
				if err != nil {
					return err
				}

				ast.Inspect(node, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkgIdent, ok := sel.X.(*ast.Ident)
					if !ok || pkgIdent.Name != "syscall" || sel.Sel.Name != "Flock" {
						return true
					}

					rel, _ := filepath.Rel(root, path)
					t.Errorf("TC-081-01 violation: direct syscall.Flock found in %s:%d (must use internal/storage)",
						rel, fset.Position(call.Pos()).Line)
					return true
				})
				return nil
			})
			if err != nil {
				t.Fatalf("failed to walk %s: %v", dir, err)
			}
		}
	})

	// TC-040-AG: 결함 워커는 프로덕션 패키지를 하나도 import 하지 않는다 (ADR 0003 C-7).
	t.Run("TC-040-AG: faultworker 의 authz-harness/ import 0건", func(t *testing.T) {
		dir := filepath.Join(root, "internal", "harness", "faultworker")
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ImportsOnly)
		if err != nil || len(pkgs) == 0 {
			t.Fatalf("failed to parse faultworker dir: %v", err)
		}
		for _, pkg := range pkgs {
			for fname, file := range pkg.Files {
				for _, imp := range file.Imports {
					if strings.HasPrefix(imp.Path.Value, `"authz-harness/`) {
						t.Errorf("faultworker must be standalone: %s imports %s", fname, imp.Path.Value)
					}
				}
			}
		}
	})
	// TC-110-01: 코어 패키지는 OS 격리 어댑터(internal/confinement)를 import 하지 않는다.
	t.Run("TC-110-01: 코어 패키지의 internal/confinement import 0건", func(t *testing.T) {
		for _, rel := range []string{"domain", "authn", "authz", "jail", "audit"} {
			dir := filepath.Join(root, "internal", rel)
			err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
				if perr != nil {
					return perr
				}
				for _, imp := range f.Imports {
					if imp.Path.Value == `"authz-harness/internal/confinement"` {
						r, _ := filepath.Rel(root, path)
						t.Errorf("TC-110-01 violation: %s imports internal/confinement", r)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("failed to walk %s: %v", dir, err)
			}
		}
	})

	// TC-130-01: 코어 패키지는 time.Now 를 직접 쓰지 않는다 (허용: RealClock.Now, measureWall).
	t.Run("TC-130-01: 코어 패키지 비제어 time.Now 0건", func(t *testing.T) {
		allowed := map[string]bool{
			"internal/domain/token.go#Now":                 true, // domain.RealClock.Now
			"internal/orchestrator/spawner.go#measureWall": true, // 프로세스 실행 벽시계 측정
		}
		var targets []string
		for _, rel := range []string{"domain", "authn", "authz", "orchestrator", "audit", "jail"} {
			targets = append(targets, filepath.Join(root, "internal", rel))
		}
		for _, dir := range targets {
			err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
				if perr != nil {
					return perr
				}
				r, _ := filepath.Rel(root, path)
				r = filepath.ToSlash(r)
				for _, decl := range f.Decls {
					fd, ok := decl.(*ast.FuncDecl)
					if !ok || fd.Body == nil {
						continue
					}
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						sel, ok := n.(*ast.SelectorExpr)
						if !ok || sel.Sel.Name != "Now" {
							return true
						}
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "time" && !allowed[r+"#"+fd.Name.Name] {
							t.Errorf("TC-130-01 violation: %s %s uses time.Now", r, fd.Name.Name)
						}
						return true
					})
				}
				return nil
			})
			if err != nil {
				t.Fatalf("failed to walk %s: %v", dir, err)
			}
		}
	})
}
