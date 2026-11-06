package harness

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// getRepoRoot 는 go.mod 가 있는 레포지토리 루트 절대경로를 반환한다(탐색은 binary.go 의 locateRepoRoot 와 같다).
func getRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := locateRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
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
			`"authz-harness/internal/authz/state"`:      true,
			`"authz-harness/internal/authz/pap"`:        true,
			`"authz-harness/internal/authn/keys"`:       true,
			`"authz-harness/internal/audit/checkpoint"`: true,
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

	// TC-080-01: internal/ 전체 프로덕션 코드의 `_ = <expr>.Log(` 감사 오류 무시 0건 검증
	t.Run("TC-080-01: internal 전체 비즈니스 코드의 감사 에러 무시(_ = ...Log) 0건 검증", func(t *testing.T) {
		if v := findIgnoredAuditLog(t, filepath.Join(root, "internal")); len(v) > 0 {
			t.Errorf("forbidden audit error ignoring '_ = ...Log':\n%s", strings.Join(v, "\n"))
		}
	})

	// TC-140-01: 코어 패키지의 log/slog·OTel import 금지 (ADR 0002 B-8)
	// 제외(의도): internal/confinement(OS 어댑터, seatbelt_darwin.go 가 slog 사용), internal/mcp, internal/cli,
	// internal/app(합성 루트), cmd — 코어가 아닌 어댑터/조립 계층이다. observe/slogadapter 도 어댑터라 제외한다.
	t.Run("TC-140-01: 코어 패키지의 log/slog·OTel import 0건 검증", func(t *testing.T) {
		for _, d := range []string{"domain", "authn", "authz", "jail", "audit", "storage", "observe", "pipeline"} {
			recursive := d != "observe"
			if v := findForbiddenLogImports(t, filepath.Join(root, "internal", d), recursive); len(v) > 0 {
				t.Errorf("forbidden logger import in core package %s:\n%s", d, strings.Join(v, "\n"))
			}
		}
	})

	// TC-020-04: 가드 변이 시험 — 위반 코드를 심으면 검출되어야 한다.
	t.Run("TC-020-04: 가드 변이 시험(slog import, _ = w.Log 검출)", func(t *testing.T) {
		dir := t.TempDir()
		src := "package x\n\nimport \"log/slog\"\n\nvar _ = slog.Default\n\nfunc f(w interface{ Log(int) error }) {\n\t_ = w.Log(1)\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if len(findForbiddenLogImports(t, dir, true)) != 1 {
			t.Error("slog import not detected")
		}
		if len(findIgnoredAuditLog(t, dir)) != 1 {
			t.Error("ignored Log error not detected")
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
			`"net"`:                               true,
			`"net/http"`:                          true,
			`"os/exec"`:                           true,
			`"authz-harness/internal/netguard"`:   true,
			`"authz-harness/internal/execguard"`:  true,
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
		for _, rel := range []string{"domain", "authn", "authz", "orchestrator", "audit", "jail", "pipeline"} {
			targets = append(targets, filepath.Join(root, "internal", rel))
		}
		for _, dir := range targets {
			for _, v := range findTimeNowUses(t, root, dir, allowed) {
				t.Errorf("TC-130-01 violation: %s uses time.Now", v)
			}
		}
	})

	// TC-170-01: domain·pdp 의 전이적(Transitive) 인프라·OS 의존성 0%
	t.Run("TC-170-01: domain·pdp 전이적 인프라 의존성 0% 검증", func(t *testing.T) {
		graph := loadInternalImportGraph(t, root)
		for _, start := range []string{modulePrefix + "internal/domain", modulePrefix + "internal/authz/pdp"} {
			if _, ok := graph[start]; !ok {
				t.Fatalf("start package not found in import graph: %s", start)
			}
			for _, v := range findTransitiveViolations(graph, start, transitiveForbidden) {
				t.Errorf("TC-170-01 violation: %s", v)
			}
		}
	})

	// TC-170-02: CLI 단일 합성 루트 일원화 및 subagent.go 의 authz/state import 0건
	t.Run("TC-170-02: CLI 직접 조립 호출 0건 및 subagent.go 의 state import 0건", func(t *testing.T) {
		cliDir := filepath.Join(root, "internal", "cli")
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, cliDir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("failed to parse cli dir: %v", err)
		}
		files := map[string]*ast.File{}
		for _, pkg := range pkgs {
			for fname, f := range pkg.Files {
				files[filepath.Base(fname)] = f
			}
		}
		if _, ok := files["subagent.go"]; !ok {
			t.Fatal("cli/subagent.go not found")
		}
		for _, v := range findDirectConstructionViolations(files) {
			t.Errorf("TC-170-02 violation: %s", v)
		}
	})

	// TC-170-03: 가드 변이 시험 — 위반을 주입하면 검사 헬퍼가 반드시 검출해야 한다(False-Pass 방지)
	t.Run("TC-170-03: 전이 의존성·CLI 직접 조립 가드 변이 검출", func(t *testing.T) {
		fake := map[string][]string{
			modulePrefix + "internal/authz/pdp":   {modulePrefix + "internal/authz/pip", "context"},
			modulePrefix + "internal/authz/pip":   {modulePrefix + "internal/authz/state"},
			modulePrefix + "internal/authz/state": {modulePrefix + "internal/storage"},
			modulePrefix + "internal/storage":     {"os", "syscall"},
		}
		if got := findTransitiveViolations(fake, modulePrefix+"internal/authz/pdp", transitiveForbidden); len(got) == 0 {
			t.Error("transitive guard failed to detect pdp -> pip -> state -> storage -> os")
		}
		clean := map[string][]string{
			modulePrefix + "internal/authz/pdp": {modulePrefix + "internal/domain"},
			modulePrefix + "internal/domain":    {"time"},
		}
		if got := findTransitiveViolations(clean, modulePrefix+"internal/authz/pdp", transitiveForbidden); len(got) != 0 {
			t.Errorf("transitive guard false positive: %v", got)
		}

		src := "package cli\nimport (\n\t\"authz-harness/internal/audit\"\n\t\"authz-harness/internal/authz/state\"\n)\n" +
			"func f() { _, _ = state.NewFileStore(\"p\"); _, _ = audit.NewJSONLWriter(\"a\") }\n"
		f, err := parser.ParseFile(token.NewFileSet(), "subagent.go", src, 0)
		if err != nil {
			t.Fatalf("parse fake cli source: %v", err)
		}
		got := findDirectConstructionViolations(map[string]*ast.File{"subagent.go": f})
		if len(got) < 3 { // NewFileStore, NewJSONLWriter, subagent.go state import
			t.Errorf("cli guard expected >=3 violations, got %v", got)
		}
		okSrc := "package cli\nfunc g() {}\n"
		okf, _ := parser.ParseFile(token.NewFileSet(), "subagent.go", okSrc, 0)
		if got := findDirectConstructionViolations(map[string]*ast.File{"subagent.go": okf}); len(got) != 0 {
			t.Errorf("cli guard false positive: %v", got)
		}
	})

	// TC-170-04: 허용 목록 — 금지 목록(TC-060-01·TC-170-01)에 없는 새 패키지도 pdp·domain 에서는 잡는다
	t.Run("TC-170-04: pdp·domain 직접 import 허용 목록 검증", func(t *testing.T) {
		graph := loadInternalImportGraph(t, root)
		for pkg, allowed := range map[string]map[string]bool{
			modulePrefix + "internal/authz/pdp": pdpAllowedImports,
			modulePrefix + "internal/domain":    domainAllowedImports,
			modulePrefix + "internal/pipeline":  pipelineAllowedImports,
		} {
			if _, ok := graph[pkg]; !ok {
				t.Fatalf("package not found in import graph: %s", pkg)
			}
			for _, imp := range findDisallowedImports(graph, pkg, allowed) {
				t.Errorf("TC-170-04 violation: %s imports %q (not in allow list)", pkg, imp)
			}
		}
	})

	// TC-020-13: pipeline 에 time.Now·log/slog 를 주입하면 가드가 검출해야 한다.
	t.Run("TC-020-13: pipeline 가드 변이 검출(time.Now, log/slog)", func(t *testing.T) {
		dir := t.TempDir()
		src := "package x\n\nimport (\n\t\"log/slog\"\n\t\"time\"\n)\n\nvar _ = slog.Default\n\nfunc f() { _ = time.Now() }\n"
		if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if len(findTimeNowUses(t, dir, dir, nil)) != 1 {
			t.Error("time.Now not detected")
		}
		if len(findForbiddenLogImports(t, dir, true)) != 1 {
			t.Error("slog import not detected")
		}
		pkg := modulePrefix + "internal/pipeline"
		if got := findDisallowedImports(map[string][]string{pkg: {"context", "time"}}, pkg, pipelineAllowedImports); len(got) != 1 || got[0] != "time" {
			t.Errorf("allow-list: want [time], got %v", got)
		}
	})

	// TC-170-05: 허용 목록 가드 변이 시험 — 목록 밖 import 를 주입하면 반드시 검출해야 한다(False-Pass 방지)
	t.Run("TC-170-05: 허용 목록 가드 변이 검출", func(t *testing.T) {
		pdp := modulePrefix + "internal/authz/pdp"
		fake := map[string][]string{pdp: {"context", "io/ioutil", modulePrefix + "internal/domain"}}
		got := findDisallowedImports(fake, pdp, pdpAllowedImports)
		if len(got) != 1 || got[0] != "io/ioutil" {
			t.Errorf("allow-list guard expected [io/ioutil], got %v", got)
		}
		clean := map[string][]string{pdp: {"context", "fmt", modulePrefix + "internal/domain"}}
		if got := findDisallowedImports(clean, pdp, pdpAllowedImports); len(got) != 0 {
			t.Errorf("allow-list guard false positive: %v", got)
		}
	})

	// TC-170-06: 관문(pep) 직접 import 허용 목록 — 장부 원본·조립·OS 패키지를 직접 가져다 쓰지 않는다
	t.Run("TC-170-06: pep 직접 import 허용 목록 검증", func(t *testing.T) {
		graph := loadInternalImportGraph(t, root)
		pkg := modulePrefix + "internal/authz/pep"
		if _, ok := graph[pkg]; !ok {
			t.Fatalf("package not found in import graph: %s", pkg)
		}
		for _, imp := range findDisallowedImports(graph, pkg, pepAllowedImports) {
			t.Errorf("TC-170-06 violation: %s imports %q (not in allow list)", pkg, imp)
		}
	})

	// TC-170-07: pep 허용 목록 가드 변이 시험 (AT-02·AT-03·AT-04)
	t.Run("TC-170-07: pep 허용 목록 가드 변이 검출", func(t *testing.T) {
		pkg := modulePrefix + "internal/authz/pep"
		base := make([]string, 0, len(pepAllowedImports)+1)
		for imp := range pepAllowedImports {
			base = append(base, imp)
		}
		cases := []struct {
			name  string
			extra string
			want  []string
		}{
			{"OS 패키지 주입", "os", []string{"os"}},
			{"장부 원본 주입", modulePrefix + "internal/authz/state", []string{modulePrefix + "internal/authz/state"}},
			{"현재 집합 그대로", "", nil},
		}
		for _, tc := range cases {
			imports := append([]string{}, base...)
			if tc.extra != "" {
				imports = append(imports, tc.extra)
			}
			got := findDisallowedImports(map[string][]string{pkg: imports}, pkg, pepAllowedImports)
			if len(got) != len(tc.want) || (len(got) == 1 && got[0] != tc.want[0]) {
				t.Errorf("%s: want %v, got %v", tc.name, tc.want, got)
			}
		}
	})
}

// findTimeNowUses 는 dir 아래 비테스트 Go 파일에서 허용 목록 밖의 time.Now 사용을 "경로 함수" 로 돌려준다.
func findTimeNowUses(t *testing.T, root, dir string, allowed map[string]bool) []string {
	t.Helper()
	var out []string
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
					out = append(out, r+" "+fd.Name.Name)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", dir, err)
	}
	return out
}

const modulePrefix = "authz-harness/"

// 직접 import 허용 목록. 항목을 추가하는 변경은 그 자체가 리뷰 대상이다.
// 추가 시 설명서 007편 Q4 「무엇을 못 잡나」도 함께 갱신한다.
var pdpAllowedImports = map[string]bool{
	"context":                        true,
	"fmt":                            true,
	"strings":                        true,
	"time":                           true,
	modulePrefix + "internal/domain": true,
}

// 관문(pep) 직접 import 허용 목록. 표준 4개와 내부 어댑터·도메인 9개로 고정한다.
// 추가 시 설명서 007편 Q4·Q5 도 함께 갱신한다.
var pepAllowedImports = map[string]bool{
	"context":                              true,
	"fmt":                                  true,
	"strings":                              true,
	"time":                                 true,
	modulePrefix + "internal/audit":        true,
	modulePrefix + "internal/authn/budget": true,
	modulePrefix + "internal/authn/token":  true,
	modulePrefix + "internal/authz/pdp":    true,
	modulePrefix + "internal/domain":       true,
	modulePrefix + "internal/execguard":    true,
	modulePrefix + "internal/jail":         true,
	modulePrefix + "internal/netguard":     true,
	modulePrefix + "internal/observe":      true,
	modulePrefix + "internal/pipeline":     true,
}

// pipeline 은 표준 라이브러리만 쓴다. 내부 패키지 import 는 허용하지 않는다.
var pipelineAllowedImports = map[string]bool{
	"context": true,
	"errors":  true,
	"fmt":     true,
}

var domainAllowedImports = map[string]bool{
	"context":        true,
	"crypto/ed25519": true,
	"crypto/sha256":  true,
	"encoding/hex":   true,
	"errors":         true,
	"fmt":            true,
	"regexp":         true,
	"strings":        true,
	"sync":           true,
	"time":           true,
}

// findDisallowedImports 는 pkg 의 직접 import 중 허용 목록에 없는 항목을 반환한다.
func findDisallowedImports(graph map[string][]string, pkg string, allowed map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, imp := range graph[pkg] {
		if !allowed[imp] && !seen[imp] {
			seen[imp] = true
			out = append(out, imp)
		}
	}
	return out
}

var transitiveForbidden = map[string]bool{
	modulePrefix + "internal/storage":          true,
	modulePrefix + "internal/authz/state":      true,
	modulePrefix + "internal/authz/pip":        true,
	modulePrefix + "internal/audit":            true,
	modulePrefix + "internal/audit/checkpoint": true,
	modulePrefix + "internal/jail":             true,
	modulePrefix + "internal/netguard":         true,
	modulePrefix + "internal/execguard":        true,
	modulePrefix + "internal/confinement":      true,
	"os":                                       true,
	"syscall":                                  true,
	"os/exec":                                  true,
	"net":                                      true,
	"net/http":                                 true,
	"path/filepath":                            true,
	"io/fs":                                    true,
}

// loadInternalImportGraph 는 internal/ 아래 패키지별 프로덕션 파일의 직접 import 집합을 만든다.
func loadInternalImportGraph(t *testing.T, root string) map[string][]string {
	t.Helper()
	graph := map[string][]string{}
	base := filepath.Join(root, "internal")
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkg := modulePrefix + filepath.ToSlash(rel)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if _, ok := graph[pkg]; !ok {
			graph[pkg] = nil
		}
		for _, imp := range f.Imports {
			graph[pkg] = append(graph[pkg], strings.Trim(imp.Path.Value, `"`))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to build import graph: %v", err)
	}
	return graph
}

// findTransitiveViolations 는 start 에서 프로젝트 내부 간선만 따라 도달 가능한 모든 import 중 금지 항목을 경로와 함께 반환한다.
// 표준 라이브러리 내부(time→os 등)는 따라가지 않는다.
func findTransitiveViolations(graph map[string][]string, start string, forbidden map[string]bool) []string {
	var out []string
	visited := map[string]bool{start: true}
	type item struct {
		pkg  string
		path string
	}
	queue := []item{{start, start}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, imp := range graph[cur.pkg] {
			if forbidden[imp] {
				out = append(out, cur.path+" -> "+imp)
				continue
			}
			if strings.HasPrefix(imp, modulePrefix+"internal/") && !visited[imp] {
				visited[imp] = true
				queue = append(queue, item{imp, cur.path + " -> " + imp})
			}
		}
	}
	return out
}

var cliForbiddenCalls = map[string]bool{
	"state.NewFileStore": true, "keys.NewFileStore": true, "token.NewFileReplayLedger": true,
	"budget.NewFileLedger": true, "audit.NewJSONLWriter": true, "exchange.NewExchangeService": true,
}

// findDirectConstructionViolations 는 CLI 파일(파일명→AST)에서 금지된 직접 생성 호출과 subagent.go 의 state import 를 찾는다.
func findDirectConstructionViolations(files map[string]*ast.File) []string {
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
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if q := id.Name + "." + sel.Sel.Name; cliForbiddenCalls[q] {
				out = append(out, name+": direct call "+q)
			}
			return true
		})
		if name == "subagent.go" {
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) == modulePrefix+"internal/authz/state" {
					out = append(out, name+": imports internal/authz/state")
				}
			}
		}
	}
	return out
}

func findForbiddenLogImports(t *testing.T, dir string, recursive bool) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "log/slog" || strings.HasPrefix(p, "go.opentelemetry.io/") {
				out = append(out, path+": "+p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

func findIgnoredAuditLog(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == "_" {
				if call, ok := as.Rhs[0].(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Log" {
						out = append(out, fmt.Sprintf("%s:%d", path, fset.Position(as.Pos()).Line))
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}
