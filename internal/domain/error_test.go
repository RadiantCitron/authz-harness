package domain_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"authz-harness/internal/domain"
)

// TC-010-01: *domain.Error 생성 및 errors.As 추출
func TestTC_010_01_ErrorCreationAndExtraction(t *testing.T) {
	sentinel := errors.New("sentinel token expired")
	domErr := domain.NewError(domain.ReasonTokenExpired, "token expired", sentinel)

	// 다중 래핑
	wrapped := fmt.Errorf("outer wrap: %w", fmt.Errorf("inner wrap: %w", domErr))

	extractedReason := domain.ReasonFromError(wrapped, "")
	if extractedReason != domain.ReasonTokenExpired {
		t.Fatalf("expected reason %s, got %s", domain.ReasonTokenExpired, extractedReason)
	}

	exitCode := domain.ExitCodeFromError(wrapped, domain.ExitInternalError)
	if exitCode != domain.ExitTokenInvalid {
		t.Fatalf("expected exit code %d, got %d", domain.ExitTokenInvalid, exitCode)
	}
}

// TC-010-02: 에러 메시지 문구 변경 불변성
func TestTC_010_02_MessageIndependence(t *testing.T) {
	sentinel := errors.New("original underlying error")
	err1 := domain.NewError(domain.ReasonTokenExpired, "English message: token expired", sentinel)
	err2 := domain.NewError(domain.ReasonTokenExpired, "완전히 다른 한글 문구: 토큰이 만료되었습니다", sentinel)

	if domain.ReasonFromError(err1, "") != domain.ReasonFromError(err2, "") {
		t.Fatalf("reasons differ despite same Reason constant: %s vs %s",
			domain.ReasonFromError(err1, ""), domain.ReasonFromError(err2, ""))
	}

	if domain.ExitCodeFromError(err1, 0) != domain.ExitCodeFromError(err2, 0) {
		t.Fatalf("exit codes differ despite same Reason constant: %d vs %d",
			domain.ExitCodeFromError(err1, 0), domain.ExitCodeFromError(err2, 0))
	}
}

// TC-010-03: 기존 센티넬 에러 errors.Is 호환성
func TestTC_010_03_SentinelCompatibility(t *testing.T) {
	sentinelSig := errors.New("invalid signature sentinel")
	domErr := domain.NewError(domain.ReasonTokenInvalidSignature, "signature fail", sentinelSig)

	if !errors.Is(domErr, sentinelSig) {
		t.Fatal("errors.Is(domErr, sentinelSig) should be true via Unwrap")
	}

	wrapped := fmt.Errorf("transport wrap: %w", domErr)
	if !errors.Is(wrapped, sentinelSig) {
		t.Fatal("errors.Is(wrapped, sentinelSig) should be true through multiple wrappers")
	}
}

// TC-010-04: 전 사유 코드(Reason) -> ExitCode 전수 매핑
func TestTC_010_04_AllReasonsMappedToExitCode(t *testing.T) {
	allReasons := []struct {
		reason   domain.Reason
		expected domain.ExitCode
	}{
		{domain.ReasonAuthorized, domain.ExitSuccess},
		{domain.ReasonAuthnUnknownClient, domain.ExitTokenInvalid},
		{domain.ReasonAuthnInvalidSecret, domain.ExitTokenInvalid},
		{domain.ReasonAuthnClientSuspended, domain.ExitTokenInvalid},
		{domain.ReasonTokenInvalidType, domain.ExitTokenInvalid},
		{domain.ReasonTokenAlgNotAllowed, domain.ExitTokenInvalid},
		{domain.ReasonTokenExpired, domain.ExitTokenInvalid},
		{domain.ReasonTokenNotYetValid, domain.ExitTokenInvalid},
		{domain.ReasonTokenInvalidIssAud, domain.ExitTokenInvalid},
		{domain.ReasonTokenSubjectMismatch, domain.ExitTokenInvalid},
		{domain.ReasonTokenReplayDetected, domain.ExitTokenInvalid},
		{domain.ReasonTokenMalformed, domain.ExitTokenInvalid},
		{domain.ReasonTokenKeyRetired, domain.ExitTokenInvalid},
		{domain.ReasonTokenKeyNotFound, domain.ExitTokenInvalid},
		{domain.ReasonTokenInvalidSignature, domain.ExitTokenInvalid},
		{domain.ReasonInvalidToken, domain.ExitTokenInvalid},
		{domain.ReasonNoActiveGrant, domain.ExitAuthzDenied},
		{domain.ReasonGrantRevoked, domain.ExitAuthzDenied},
		{domain.ReasonSubjectEpochRevoked, domain.ExitAuthzDenied},
		{domain.ReasonTokenInsufficientScope, domain.ExitAuthzDenied},
		{domain.ReasonDelegationScopeExceeded, domain.ExitAuthzDenied},
		{domain.ReasonDelegationTTLExceeded, domain.ExitAuthzDenied},
		{domain.ReasonDelegationDepthExceeded, domain.ExitAuthzDenied},
		{domain.ReasonDelegationSelfLoop, domain.ExitAuthzDenied},
		{domain.ReasonDelegationScopeEmpty, domain.ExitAuthzDenied},
		{domain.ReasonPathViolation, domain.ExitPathViolation},
		{domain.ReasonPathTraversal, domain.ExitPathViolation},
		{domain.ReasonSymlinkEscape, domain.ExitPathViolation},
		{domain.ReasonInvalidPath, domain.ExitPathViolation},
		{domain.ReasonInvalidArguments, domain.ExitBadInput},
		{domain.ReasonMissingTraceContext, domain.ExitBadInput},
		{domain.ReasonAuditLogFailed, domain.ExitAuditFailure},
		{domain.ReasonAuditIntegrityBroken, domain.ExitAuditFailure},
		{domain.ReasonAuditTruncationDetected, domain.ExitAuditFailure},
		{domain.ReasonAuditCheckpointMismatch, domain.ExitAuditFailure},
		{domain.ReasonApprovalRequired, domain.ExitApprovalRequired},
		{domain.ReasonApprovalExpired, domain.ExitApprovalRequired},
		{domain.ReasonApprovalMismatch, domain.ExitApprovalRequired},
		{domain.ReasonConfinementUnavailable, domain.ExitInternalError},
		{domain.Reason("UNKNOWN_RANDOM_REASON"), domain.ExitInternalError},
	}

	for _, tc := range allReasons {
		got := domain.ExitCodeForReason(tc.reason)
		if got != tc.expected {
			t.Errorf("reason %s: expected exit code %d, got %d", tc.reason, tc.expected, got)
		}

		err := domain.NewError(tc.reason, "msg", nil)
		if err.ExitCode != tc.expected {
			t.Errorf("NewError for reason %s: expected ExitCode %d, got %d", tc.reason, tc.expected, err.ExitCode)
		}
	}
}

// TC-010-10: 코드베이스 전역 strings.Contains(err.Error()) 제로 검증 (AST 스캐너)
func TestTC_010_10_NoStringContainsOnErrors(t *testing.T) {
	root := filepath.Join("..") // internal 디렉터리
	fset := token.NewFileSet()

	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !filepath.HasPrefix(filepath.Ext(path), ".go") {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		node, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}

		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// strings.Contains 호출인지 확인
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Contains" {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "strings" {
				return true
			}

			if len(call.Args) >= 1 {
				// arg0이 x.Error() 형태인지 검사
				if argCall, ok := call.Args[0].(*ast.CallExpr); ok {
					if argSel, ok := argCall.Fun.(*ast.SelectorExpr); ok && argSel.Sel.Name == "Error" {
						pos := fset.Position(call.Pos())
						violations = append(violations, fmt.Sprintf("%s: strings.Contains(....Error(), ...)", pos))
					}
				}
			}

			return true
		})

		return nil
	})

	if err != nil {
		t.Fatalf("failed to scan internal/: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("AP-10 violation detected! Found %d strings.Contains(*.Error(), ...) call(s):\n%s",
			len(violations), violations)
	}
}

// TC-090-01: domain.Error 는 단계 필드를 갖지 않는다. 단계는 엔진이 안다.
func TestError_HasNoStageField(t *testing.T) {
	if _, ok := reflect.TypeOf(domain.Error{}).FieldByName("Stage"); ok {
		t.Fatal("domain.Error must not have a Stage field")
	}
}
