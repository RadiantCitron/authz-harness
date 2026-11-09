// Package domain 은 시스템 전역 표준 도메인 에러(domain.Error) 및 종료코드 결정론적 매핑 로직을 제공한다.
//
// [아키텍처 가드레일 준수: 문자열 에러 파싱 금지 원칙 (TC-060-03)]
// 본 리포지토리는 에러 원인을 판정할 때 strings.Contains(err.Error(), "...") 같은 문자열 기반 파싱을 일절 금지한다.
// 문자열 파싱은 에러 메시지 변경 시 은밀한 버그를 유발하고 보안 판정 누락을 낳기 때문이다.
// 대신 표준 errors.As 를 통해 에러 체인 내의 *domain.Error 구조체를 찾아 정확한 Reason 상수와 ExitCode 를 추출한다.
//
// [Fail-Closed 및 결정론적 종료 코드 매핑]
// 모든 판정 사유(Reason)는 ExitCodeForReason 순수 함수를 거쳐 표준 프로세스 종료 코드(ExitSuccess=0, 11~18)로
// 1:1 결정론적으로 매핑된다. 정의되지 않은 사유는 안전하게 ExitInternalError(16)로 처리된다.
package domain

import (
	"errors"
	"fmt"
)

// Error 는 구체적인 사유 코드(Reason)와 표준 종료 코드(ExitCode)를 내장한 구조화된 도메인 에러다.
type Error struct {
	// Reason 은 판정 및 실패의 고유 사유 코드다 (예: ReasonTokenExpired, ReasonPathViolation).
	Reason Reason

	// ExitCode 는 프로세스 종료 시 반환할 표준 정수 코드다 (예: 11, 12, 13).
	ExitCode ExitCode

	// Message 는 개발자 및 감사 로그용 설명 메시지다.
	Message string

	// Cause 는 이 에러를 유발한 기저 원인 에러다 (nil 일 수 있음).
	Cause error
}

// Error 는 Go 표준 error 인터페이스를 구현한다.
// 메시지 뒤에 사유 코드(Reason)를 괄호로 명시하여 로그 출력 시 즉각 식별 가능하게 한다.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v (%s)", e.Message, e.Cause, e.Reason)
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Reason)
}

// Unwrap 은 Go 1.13+ errors.Is 및 errors.As 체인 탐색을 지원하는 규약 메서드다.
// 원인 에러(Cause)를 반환함으로써 상위 호출자가 기저 OS/I/O 에러를 타입 안전하게 탐색할 수 있다.
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError 는 사유 코드, 메시지, 원인 에러를 받아 표준 *domain.Error 를 생성한다.
// ExitCode 는 ExitCodeForReason(reason) 을 통해 자동으로 안전하게 결정된다.
func NewError(reason Reason, message string, cause error) *Error {
	return &Error{
		Reason:   reason,
		ExitCode: ExitCodeForReason(reason),
		Message:  message,
		Cause:    cause,
	}
}

// WrapError 는 원인 에러 cause 를 감싸 표준 *domain.Error 로 변환한다.
// cause 가 nil 이면 nil 을 반환하여 호출 측의 에러 처리 분기를 간결하게 유지한다.
func WrapError(reason Reason, cause error) *Error {
	if cause == nil {
		return nil
	}
	return NewError(reason, cause.Error(), cause)
}

// ReasonFromError 는 에러 체인을 errors.As 로 순회하여 가장 안쪽의 *domain.Error 로부터 Reason 을 추출한다.
// 문자열 파싱을 일절 수행하지 않으며, 체인에 domain.Error 가 없으면 fallback 사유를 반환한다.
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

// ExitCodeFromError 는 에러 체인을 errors.As 로 순회하여 표준 ExitCode 를 추출한다.
// 체인에 domain.Error 가 없으면 fallback 종료 코드를 반환한다.
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

// ExitCodeForReason 은 Reason 상수로부터 결정론적 ExitCode(0, 11~18)를 산출하는 순수 매핑 함수다.
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
		ReasonDelegationScopeEmpty,
		ReasonDelegationBudgetExceeded,
		ReasonBudgetExhausted,
		ReasonEgressDenied,
		ReasonExecNotAllowed,
		ReasonExecArgRejected,
		ReasonToolLimitExceeded:
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
		ReasonAuditIntegrityBroken,
		ReasonAuditTailIncomplete,
		ReasonAuditTruncationDetected,
		ReasonAuditCheckpointMismatch:
		return ExitAuditFailure // 15
	case ReasonResourceTimeout,
		ReasonResourceOutputLimit:
		return ExitResourceLimit // 17
	case ReasonApprovalRequired,
		ReasonApprovalExpired,
		ReasonApprovalMismatch:
		return ExitApprovalRequired // 18
	case ReasonSubprocessAbnormalExit,
		ReasonConfinementUnavailable:
		return ExitInternalError // 16
	default:
		return ExitInternalError // 16
	}
}
