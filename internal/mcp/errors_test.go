package mcp

import (
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

func TestMapSubprocessError(t *testing.T) {
	tests := []struct {
		name           string
		exitCode       int
		rawReason      string
		rawErrMsg      string
		expectedReason string
		expectedText   string
	}{
		{
			name:           "TC-040-01: 스코프 부족 거부 (ExitCode 12)",
			exitCode:       int(domain.ExitAuthzDenied),
			rawReason:      string(domain.ReasonTokenInsufficientScope),
			rawErrMsg:      "token insufficient scope",
			expectedReason: "TOKEN_INSUFFICIENT_SCOPE",
			expectedText:   "[TOKEN_INSUFFICIENT_SCOPE] token insufficient scope (exit code 12)",
		},
		{
			name:           "TC-040-02: 만료 토큰 거부 (ExitCode 11)",
			exitCode:       int(domain.ExitTokenInvalid),
			rawReason:      string(domain.ReasonTokenExpired),
			rawErrMsg:      "token has expired",
			expectedReason: "TOKEN_EXPIRED",
			expectedText:   "[TOKEN_EXPIRED] token has expired (exit code 11)",
		},
		{
			name:           "TC-010-06a: 승인 필요 (ExitCode 18, 사유 복원)",
			exitCode:       int(domain.ExitApprovalRequired),
			rawReason:      "",
			rawErrMsg:      "approval required",
			expectedReason: "APPROVAL_REQUIRED",
			expectedText:   "[APPROVAL_REQUIRED] approval required (exit code 18)",
		},
		{
			name:           "TC-010-06b: 승인 만료 (사유 보존)",
			exitCode:       int(domain.ExitApprovalRequired),
			rawReason:      string(domain.ReasonApprovalExpired),
			rawErrMsg:      "approval expired",
			expectedReason: "APPROVAL_EXPIRED",
			expectedText:   "[APPROVAL_EXPIRED] approval expired (exit code 18)",
		},
		{
			name:           "ExitResourceLimit (17) -> RESOURCE_TIMEOUT 사유 복원",
			exitCode:       int(domain.ExitResourceLimit),
			rawReason:      "",
			rawErrMsg:      "context deadline exceeded",
			expectedReason: "RESOURCE_TIMEOUT",
			expectedText:   "[RESOURCE_TIMEOUT] context deadline exceeded (exit code 17)",
		},
		{
			name:           "TC-040-03: 알 수 없는 종료 코드 -> ReasonInternalError",
			exitCode:       99,
			rawReason:      "",
			rawErrMsg:      "",
			expectedReason: "INTERNAL_ERROR",
			expectedText:   "[INTERNAL_ERROR] execution denied with exit code 99 (reason: INTERNAL_ERROR) (exit code 99)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := MapSubprocessError(tt.exitCode, tt.rawReason, tt.rawErrMsg)
			if !res.IsError {
				t.Fatalf("expected IsError=true")
			}
			if len(res.Content) != 1 {
				t.Fatalf("expected 1 content, got %d", len(res.Content))
			}
			if !strings.Contains(res.Content[0].Text, tt.expectedReason) {
				t.Errorf("expected reason %s in text, got: %s", tt.expectedReason, res.Content[0].Text)
			}
			if res.Content[0].Text != tt.expectedText {
				t.Errorf("expected text %q, got %q", tt.expectedText, res.Content[0].Text)
			}
		})
	}
}

func TestTokenRedaction_ZeroLeakage(t *testing.T) {
	// TC-040-04: 오류 메시지나 출력에 원시 JWT 토큰이 포함된 경우 [REDACTED_TOKEN]으로 마스킹
	// gitleaks 정적 분석 오탐을 방지하기 위해 런타임에 결합하여 테스트용 JWT 형태 구성
	part1 := "eyJhbGciOiJFZERTQSI"
	part2 := "eyJzdWIiOiJ3b3JrZXItMDEifQ"
	part3 := "sig1234567890abcdef"
	rawToken := part1 + "." + part2 + "." + part3
	leakMsg := "failed to verify token: " + rawToken + " in request"

	sanitized := sanitizeMessage(leakMsg)
	if strings.Contains(sanitized, rawToken) {
		t.Errorf("token was not redacted: %s", sanitized)
	}
	if !strings.Contains(sanitized, "[REDACTED_TOKEN]") {
		t.Errorf("expected [REDACTED_TOKEN] placeholder, got: %s", sanitized)
	}

	if domain.ContainsRawToken(sanitized) {
		t.Errorf("sanitized message still contains raw token pattern")
	}

	res := MapSubprocessError(int(domain.ExitTokenInvalid), "TOKEN_INVALID", leakMsg)
	if domain.ContainsRawToken(res.Content[0].Text) {
		t.Errorf("MapSubprocessError leaked raw token: %s", res.Content[0].Text)
	}
}

// TC-010-04: 구조화 필드가 채워지고 원시 토큰이 어디에도 노출되지 않는다.
func TestMapSubprocessError_StructuredContent(t *testing.T) {
	raw := "bad token eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl end"
	res := MapSubprocessError(int(domain.ExitAuthzDenied), "NO_ACTIVE_GRANT", raw)
	sc := res.StructuredContent
	if sc == nil {
		t.Fatal("StructuredContent is nil")
	}
	if sc.ExitCode != 12 || sc.Reason != domain.Reason("NO_ACTIVE_GRANT") {
		t.Fatalf("unexpected detail: %+v", sc)
	}
	if domain.ContainsRawToken(sc.Message) || domain.ContainsRawToken(res.Content[0].Text) {
		t.Fatal("raw token leaked")
	}
}
