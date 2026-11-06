package mcp

import (
	"fmt"

	"authz-harness/internal/domain"
)

// ErrorDetail 은 도구 실행 거부 시 반환되는 구조화된 메타데이터다.
type ErrorDetail struct {
	ExitCode int           `json:"exit_code"`
	Reason   domain.Reason `json:"reason"`
	Message  string        `json:"message"`
}

// MapSubprocessError 는 자식 프로세스의 종료 코드와 Reason을 안전하게 정제하여
// 원시 토큰 및 민감한 내부 상세가 노출되지 않는 ToolExecutionResult 로 사상한다.
func MapSubprocessError(exitCode int, rawReason string, rawErrMsg string) *ToolExecutionResult {
	reason := domain.Reason(rawReason)
	if reason == "" {
		switch domain.ExitCode(exitCode) {
		case domain.ExitTokenInvalid:
			reason = domain.ReasonInvalidToken
		case domain.ExitAuthzDenied:
			reason = domain.ReasonNoActiveGrant
		case domain.ExitPathViolation:
			reason = domain.ReasonPathViolation
		case domain.ExitBadInput:
			reason = domain.ReasonInvalidArguments
		case domain.ExitAuditFailure:
			reason = domain.ReasonAuditLogFailed
		case domain.ExitResourceLimit:
			reason = domain.ReasonResourceTimeout
		case domain.ExitApprovalRequired:
			reason = domain.ReasonApprovalRequired
		default:
			reason = domain.ReasonInternalError
		}
	}

	sanitizedMsg := sanitizeMessage(rawErrMsg)
	if sanitizedMsg == "" {
		sanitizedMsg = fmt.Sprintf("execution denied with exit code %d (reason: %s)", exitCode, reason)
	}

	detail := fmt.Sprintf("[%s] %s (exit code %d)", reason, sanitizedMsg, exitCode)

	return &ToolExecutionResult{
		Content: []ToolContent{
			{Type: "text", Text: detail},
		},
		IsError: true,
		StructuredContent: &ErrorDetail{
			ExitCode: exitCode,
			Reason:   reason,
			Message:  sanitizedMsg,
		},
	}
}

// sanitizeMessage 는 메시지 내에 원시 JWT 토큰이 포함되어 있을 경우 domain.RedactRawTokens 로 마스킹한다.
func sanitizeMessage(msg string) string {
	if msg == "" {
		return ""
	}
	return domain.RedactRawTokens(msg)
}
