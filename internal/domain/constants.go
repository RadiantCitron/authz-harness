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

	// ReasonAuthnUnknownClient 는 등록되지 않은 client_id로 인증을 시도했음을 나타낸다.
	ReasonAuthnUnknownClient Reason = "AUTHN_UNKNOWN_CLIENT"

	// ReasonAuthnInvalidSecret 은 클라이언트 secret이 일치하지 않음을 나타낸다.
	ReasonAuthnInvalidSecret Reason = "AUTHN_INVALID_SECRET"

	// ReasonAuthnClientSuspended 는 정지 또는 비활성화된 클라이언트임을 나타낸다.
	ReasonAuthnClientSuspended Reason = "AUTHN_CLIENT_SUSPENDED"

	// ReasonTokenInvalidType 은 토큰 헤더의 typ이 at+jwt가 아님을 나타낸다.
	ReasonTokenInvalidType Reason = "TOKEN_INVALID_TYPE"

	// ReasonTokenAlgNotAllowed 는 허용되지 않은 서명 알고리즘(alg: none 또는 EdDSA 외)임을 나타낸다.
	ReasonTokenAlgNotAllowed Reason = "TOKEN_ALG_NOT_ALLOWED"

	// ReasonTokenExpired 는 토큰의 exp(만료 시각)가 경과했음을 나타낸다.
	ReasonTokenExpired Reason = "TOKEN_EXPIRED"

	// ReasonTokenNotYetValid 는 토큰의 nbf(유효 시작 시각)에 도달하지 않았음을 나타낸다.
	ReasonTokenNotYetValid Reason = "TOKEN_NOT_YET_VALID"

	// ReasonTokenInvalidIssAud 는 iss 또는 aud 클레임이 기대값과 일치하지 않음을 나타낸다.
	ReasonTokenInvalidIssAud Reason = "TOKEN_INVALID_ISS_AUD"

	// ReasonTokenSubjectMismatch 는 sub 클레임이 기대값과 일치하지 않음을 나타낸다.
	ReasonTokenSubjectMismatch Reason = "TOKEN_SUBJECT_MISMATCH"

	// ReasonTokenReplayDetected 는 이미 소비된 jti를 재사용한 공격임을 나타낸다.
	ReasonTokenReplayDetected Reason = "TOKEN_REPLAY_DETECTED"

	// ReasonTokenMalformed 는 JWT 구조가 3단 점 분리 형태가 아니거나 JSON 역직렬화에 실패했음을 나타낸다.
	ReasonTokenMalformed Reason = "TOKEN_MALFORMED"

	// ReasonTokenKeyRetired 는 서명에 사용된 키가 폐기(retired)되어 검증 거부됨을 나타낸다.
	ReasonTokenKeyRetired Reason = "TOKEN_KEY_RETIRED"

	// ReasonTokenKeyNotFound 는 토큰 kid에 일치하는 공개키가 JWKS에 존재하지 않음을 나타낸다.
	ReasonTokenKeyNotFound Reason = "TOKEN_KEY_NOT_FOUND"

	// ReasonTokenInvalidSignature 는 토큰의 암호학적 디지털 서명이 일치하지 않음을 나타낸다.
	ReasonTokenInvalidSignature Reason = "TOKEN_INVALID_SIGNATURE"
)
