package domain

import (
	"errors"
	"fmt"
)

// Error 는 사유 코드(Reason), 발생 관문(Stage), 종료 코드(ExitCode)를 내장한 표준 도메인 에러다.
type Error struct {
	Reason   Reason
	Stage    string
	ExitCode ExitCode
	Message  string
	Cause    error
}

// Error 는 표준 error 인터페이스를 구현한다.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v (%s)", e.Message, e.Cause, e.Reason)
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Reason)
}

// Unwrap 은 errors.Is 및 errors.As 체인 탐색을 지원한다.
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError 는 원인 에러와 사유 코드로 표준 *domain.Error 를 생성하며, Reason 에 대응하는 표준 ExitCode 를 자동 매핑한다.
func NewError(reason Reason, stage, message string, cause error) *Error {
	return &Error{
		Reason:   reason,
		Stage:    stage,
		ExitCode: ExitCodeForReason(reason),
		Message:  message,
		Cause:    cause,
	}
}

// WrapError 는 원인 에러를 기반으로 표준 *domain.Error 를 생성한다. cause 가 nil 이면 nil 을 반환한다.
func WrapError(reason Reason, stage string, cause error) *Error {
	if cause == nil {
		return nil
	}
	return NewError(reason, stage, cause.Error(), cause)
}

// ReasonFromError 는 에러 체인에서 *domain.Error 를 찾아 Reason 을 반환한다 (문자열 파싱 일체 없음).
func ReasonFromError(err error, fallback Reason) Reason {
	if err == nil {
		return fallback
	}
	var domainErr *Error
	if errors.As(err, &domainErr) {
		if domainErr.Reason != "" {
			return domainErr.Reason
		}
	}
	return fallback
}

// ExitCodeFromError 는 에러 체인에서 *domain.Error 를 찾아 표준 ExitCode 를 반환한다.
func ExitCodeFromError(err error, fallback ExitCode) ExitCode {
	if err == nil {
		return fallback
	}
	var domainErr *Error
	if errors.As(err, &domainErr) {
		return domainErr.ExitCode
	}
	return fallback
}

// ExitCodeForReason 은 Reason 상수로부터 결정론적 ExitCode(0, 11~16)를 산출하는 순수 매핑 함수다.
func ExitCodeForReason(r Reason) ExitCode {
	switch r {
	case ReasonAuthorized:
		return ExitSuccess // 0
	case ReasonAuthnUnknownClient,
		ReasonAuthnInvalidSecret,
		ReasonAuthnClientSuspended,
		ReasonTokenInvalidType,
		ReasonTokenAlgNotAllowed,
		ReasonTokenExpired,
		ReasonTokenNotYetValid,
		ReasonTokenInvalidIssAud,
		ReasonTokenSubjectMismatch,
		ReasonTokenReplayDetected,
		ReasonTokenMalformed,
		ReasonTokenKeyRetired,
		ReasonTokenKeyNotFound,
		ReasonTokenInvalidSignature,
		ReasonInvalidToken:
		return ExitTokenInvalid // 11
	case ReasonNoActiveGrant,
		ReasonGrantRevoked,
		ReasonSubjectEpochRevoked,
		ReasonTokenInsufficientScope,
		ReasonDelegationScopeExceeded,
		ReasonDelegationTTLExceeded,
		ReasonDelegationDepthExceeded,
		ReasonDelegationSelfLoop,
		ReasonDelegationScopeEmpty:
		return ExitAuthzDenied // 12
	case ReasonPathViolation,
		ReasonPathTraversal,
		ReasonSymlinkEscape,
		ReasonInvalidPath:
		return ExitPathViolation // 13
	case ReasonInvalidArguments,
		ReasonMissingTraceContext:
		return ExitBadInput // 14
	case ReasonAuditLogFailed,
		ReasonAuditIntegrityBroken:
		return ExitAuditFailure // 15
	default:
		return ExitInternalError // 16
	}
}
