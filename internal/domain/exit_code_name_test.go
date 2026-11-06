package domain_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"authz-harness/internal/domain"
)

// 계획 014 S1: 종료 코드의 이름은 domain 이 한 곳에서 갖는다.

// N1: 요구 사항 표(코드 → 이름)를 시험에 직접 적는다.
func TestExitCodeName_KnownCodes(t *testing.T) {
	tests := []struct {
		code domain.ExitCode
		want string
	}{
		{0, "ExitSuccess"},
		{11, "ExitTokenInvalid"},
		{12, "ExitAuthzDenied"},
		{13, "ExitPathViolation"},
		{14, "ExitBadInput"},
		{15, "ExitAuditFailure"},
		{16, "ExitInternalError"},
		{17, "ExitResourceLimit"},
		{18, "ExitApprovalRequired"},
	}
	for _, tc := range tests {
		if got := domain.ExitCodeName(tc.code); got != tc.want {
			t.Errorf("ExitCodeName(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

// N3: 정의되지 않은 값은 Unknown.
func TestExitCodeName_UndefinedIsUnknown(t *testing.T) {
	for _, c := range []domain.ExitCode{99, -1, 19, 1, 10} {
		if got := domain.ExitCodeName(c); got != "Unknown" {
			t.Errorf("ExitCodeName(%d) = %q, want Unknown", c, got)
		}
	}
}

// N2: 완전성. constants.go 에 선언된 ExitCode 상수를 소스에서 모두 찾아, 각 값의 이름이 선언의 식별자와 같은지 본다.
// 기대값을 구현(이름 표)이 아니라 소스 선언에서 얻으므로, 새 코드를 정의하고 이름을 안 적으면 실패한다.
func TestExitCodeName_CoversEveryDeclaredConstant(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "constants.go", nil, 0)
	if err != nil {
		t.Fatalf("constants.go 를 읽지 못함 (조용히 통과하지 않는다): %v", err)
	}

	found := 0
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil {
				continue
			}
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "ExitCode" {
				continue
			}
			for i, nameIdent := range vs.Names {
				if i >= len(vs.Values) {
					t.Fatalf("%s: 값이 없는 ExitCode 상수는 지원하지 않음 (iota 로 바꿨다면 이 시험도 고칠 것)", nameIdent.Name)
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					t.Fatalf("%s: 정수 리터럴이 아닌 ExitCode 상수는 지원하지 않음", nameIdent.Name)
				}
				n, convErr := strconv.Atoi(lit.Value)
				if convErr != nil {
					t.Fatalf("%s: %v", nameIdent.Name, convErr)
				}
				found++
				if got := domain.ExitCodeName(domain.ExitCode(n)); got != nameIdent.Name {
					t.Errorf("ExitCodeName(%d) = %q, want %q — 이름 표(exitCodeNames)에 추가할 것", n, got, nameIdent.Name)
				}
			}
		}
	}
	if found < 9 {
		t.Fatalf("ExitCode 상수를 %d개만 찾음 (9개 이상이어야 함): 파싱이 어긋났을 수 있음", found)
	}
}
