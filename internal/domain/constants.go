package domain

// ExitCode 는 마스터 로드맵 §13 및 프로세스 종료 규약에 정의된 표준 프로세스 종료 코드다.
type ExitCode int

const (
	// ExitSuccess 는 요청이 성공적으로 인가되고 수행되었음을 의미한다.
	ExitSuccess ExitCode = 0

	// ExitTokenInvalid 는 토큰 누락, 위조, 서명 실패, 파싱 실패를 의미한다.
	ExitTokenInvalid ExitCode = 11

	// ExitAuthzDenied 는 토큰은 유효하나 PDP 인가에서 거부되었음을 의미한다. (권한 없음, 회수됨, Epoch 불일치 등)
	ExitAuthzDenied ExitCode = 12

	// ExitPathViolation 은 PEP 샌드박스 파일 접근 경계 침범(탈출 시도 등)을 의미한다.
	ExitPathViolation ExitCode = 13

	// ExitBadInput 은 CLI 플래그 또는 입력 인자 오류를 의미한다.
	ExitBadInput ExitCode = 14

	// ExitAuditFailure 는 감사 추적 기록 실패 또는 무결성 훼손을 의미한다.
	ExitAuditFailure ExitCode = 15

	// ExitInternalError 는 시스템 예외, I/O 실패 등 복구 불가능한 내부 오류를 의미한다.
	ExitInternalError ExitCode = 16
)

// Reason 은 PDP 인가 결정 및 검증 실패의 구체적인 판정 사유 코드다.
type Reason string

const (
	// ReasonAuthorized 는 정책 검증을 통과하여 정상 승인되었음을 나타낸다.
	ReasonAuthorized Reason = "AUTHORIZED"

	// ReasonNoActiveGrant 는 대상 요청에 일치하는 활성 Grant가 존재하지 않음을 나타낸다.
	ReasonNoActiveGrant Reason = "NO_ACTIVE_GRANT"

	// ReasonGrantRevoked 는 Grant가 명시적으로 회수(revoked)되었음을 나타낸다.
	ReasonGrantRevoked Reason = "GRANT_REVOKED"

	// ReasonSubjectEpochRevoked 는 Subject의 Security Epoch가 증가하여 이전 토큰/권한이 일괄 무효화되었음을 나타낸다.
	ReasonSubjectEpochRevoked Reason = "SUBJECT_EPOCH_REVOKED"

	// ReasonTokenInsufficientScope 는 토큰의 스코프가 요청된 액션 및 리소스를 충족하지 못함을 나타낸다.
	ReasonTokenInsufficientScope Reason = "TOKEN_INSUFFICIENT_SCOPE"

	// ReasonPathViolation 은 지정된 리소스 경로가 허용된 샌드박스/격리 영역을 벗어남을 나타낸다.
	ReasonPathViolation Reason = "PATH_VIOLATION"

	// ReasonInvalidToken 은 토큰이 만료되었거나 서명이 유효하지 않음을 나타낸다.
	ReasonInvalidToken Reason = "INVALID_TOKEN"

	// ReasonTokenKeyRetired 는 서명에 사용된 키가 폐기(retired)되어 검증 거부됨을 나타낸다.
	ReasonTokenKeyRetired Reason = "TOKEN_KEY_RETIRED"

	// ReasonTokenKeyNotFound 는 토큰 kid에 일치하는 공개키가 JWKS에 존재하지 않음을 나타낸다.
	ReasonTokenKeyNotFound Reason = "TOKEN_KEY_NOT_FOUND"

	// ReasonTokenInvalidSignature 는 토큰의 암호학적 디지털 서명이 일치하지 않음을 나타낸다.
	ReasonTokenInvalidSignature Reason = "TOKEN_INVALID_SIGNATURE"
)
