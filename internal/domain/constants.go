// Package domain 은 authz-harness 전체 시스템의 단일 진실 공급원(Single Source of Truth)이자 공통 어휘 사전이다.
//
// [아키텍처 위치 및 핵심 원칙]
// 1. 제로 외부 의존성:
//    - domain 패키지는 표준 라이브러리 외에 하위 비즈니스 모듈(pdp, pep, authn, audit 등)을 일절 import 하지 않는다.
//    - 최하위 계층에 위치하여 모든 상위/동위 컴포넌트가 공통 어휘(종료코드, 판정사유, 토큰모델, 에러타입)로 소통하도록 보장한다.
// 2. 결정론적 불변성 (Determinism & Invariance):
//    - 판정 사유(Reason)로부터 프로세스 종료 코드(ExitCode)로의 매핑은 오직 순수 함수 ExitCodeForReason 에 의해서만 이루어진다.
//    - 에러 검출 시 문자열 파싱(strings.Contains 등)을 엄격히 금지하고, 구조화된 도메인 에러(domain.Error)의 Reason 타입을 검사한다.
//
// [컴포넌트 간 상호 참조 (Cross-Referencing)]
// - PEP 인가 관문: internal/authz/pep/gateway.go (10단계 검문소에서 ExitCode 및 Reason 발생)
// - PDP 인가 두뇌: internal/authz/pdp/service.go (Evaluate 순수 함수에서 Reason 판정)
// - 키 관리자: internal/authn/keys/manager.go (키 상태 및 서명 검증 실패 사유)
// - 토큰 검증기: internal/authn/token/verifier.go (JWT 파싱, 서명, 만료, 리플레이 검증)
// - 단일 조립소: internal/app/builder.go (BuildStack 에서 전체 컴포넌트에 도메인 규약 주입)
package domain

// ExitCode 는 마스터 로드맵 §13 및 프로세스 종료 규약에 정의된 표준 프로세스 종료 코드다.
// 자식 워커 프로세스, CLI 명령어, 서브에이전트가 종료될 때 OS 레벨로 반환하는 표준 정수값이다.
type ExitCode int

const (
	// DefaultIssuer 는 전 시스템 표준 토큰 발급자 식별자다 (iss 클레임).
	DefaultIssuer = "authz-harness"

	// DefaultAudience 는 전 시스템 표준 토큰 수신 대상 식별자다 (aud 클레임).
	DefaultAudience = "authz-harness"
)

const (
	// ExitSuccess (0) 는 요청이 성공적으로 인가되고 집행되었음을 의미한다.
	// PEP 10단계를 모두 통과하고 도구 실행(execute) 및 사후 정산(settle)까지 정상 완료된 상태다.
	ExitSuccess ExitCode = 0

	// ExitTokenInvalid (11) 는 토큰 누락, 위조, 서명 실패, 파싱 실패, 만료(exp), 미도래(nbf)를 의미한다.
	// 발생 지점: PEP 2단계(authn), 토큰 검증기(token.Verifier), 키 관리자(keys.Manager).
	ExitTokenInvalid ExitCode = 11

	// ExitAuthzDenied (12) 는 토큰은 유효하나 PDP 인가에서 거부되었음을 의미한다.
	// 발생 사유: 활성 Grant 없음, 권한 회수(Revoked), 주체 Epoch 불일치, 토큰 스코프 불충분 등.
	// 발생 지점: PEP 3단계(authz), PDP 인가 두뇌(pdp.Service).
	ExitAuthzDenied ExitCode = 12

	// ExitPathViolation (13) 은 PEP 샌드박스 파일 접근 경계 침범(탈출 시도 등)을 의미한다.
	// 발생 사유: ../ 경로 순회(Path Traversal), 심볼릭 링크 탈출, 샌드박스 루트 외부 접근.
	// 발생 지점: PEP 4단계(boundary), 파일시스템 격리소(jail.Jail).
	ExitPathViolation ExitCode = 13

	// ExitBadInput (14) 은 CLI 플래그, 입력 인자, JSON 형식 오류, 필수 헤더 누락을 의미한다.
	// 발생 지점: PEP 1단계(input), CLI 플래그 파서(internal/cli).
	ExitBadInput ExitCode = 14

	// ExitAuditFailure (15) 는 감사 추적 기록 실패 또는 무결성 훼손을 의미한다.
	// Fail-Closed 보안 원칙에 따라 감사 로그(audit.jsonl) 기록에 실패하면 인가 작업도 강제 중단된다.
	// 발생 지점: PEP 8단계(precommit_audit), 감사 장부 기록기(audit.Writer).
	ExitAuditFailure ExitCode = 15

	// ExitInternalError (16) 는 시스템 예외, I/O 실패, 네트워크 연결 실패 등 복구 불가능한 내부 오류를 의미한다.
	// 발생 지점: PEP 9단계(execute) 도구 실행 실패, 저장소(storage) 입출력 실패.
	ExitInternalError ExitCode = 16

	// ExitResourceLimit (17) 는 부모 스포너가 강제한 자원·수명 한계(시간 초과, 출력 크기 초과)를 의미한다.
	// 발생 지점: 부모 프로세스 감시 스포너(internal/orchestrator/spawner.go).
	ExitResourceLimit ExitCode = 17

	// ExitApprovalRequired (18) 는 PDP 가 ask(사람 승인 필요)로 판정했으나 유효한 1회용 승인이 없음을 의미한다.
	// 승인이 없거나, 만료되었거나, 인자 지문(ArgHash)이 불일치하는 경우 deny 와 마찬가지로 Fail-Closed 처리된다.
	// 발생 지점: PEP 6단계(approval), 승인 상태 저장소(state.Store).
	ExitApprovalRequired ExitCode = 18
)

// exitCodeNames 는 종료 코드의 이름(Go 식별자)이다. 새 ExitCode 상수를 정의하면 여기에도 적어야 하며,
// 빠뜨리면 TestExitCodeName_CoversEveryDeclaredConstant 가 실패한다.
var exitCodeNames = map[ExitCode]string{
	ExitSuccess:          "ExitSuccess",
	ExitTokenInvalid:     "ExitTokenInvalid",
	ExitAuthzDenied:      "ExitAuthzDenied",
	ExitPathViolation:    "ExitPathViolation",
	ExitBadInput:         "ExitBadInput",
	ExitAuditFailure:     "ExitAuditFailure",
	ExitInternalError:    "ExitInternalError",
	ExitResourceLimit:    "ExitResourceLimit",
	ExitApprovalRequired: "ExitApprovalRequired",
}

// ExitCodeName 은 종료 코드의 이름을 돌려준다. 정의되지 않은 값은 "Unknown" 이다.
// 화면 등 소비처는 이름 표를 따로 들지 않고 이 함수를 쓴다.
func ExitCodeName(c ExitCode) string {
	if name, ok := exitCodeNames[c]; ok {
		return name
	}
	return "Unknown"
}

// Reason 은 PDP 인가 결정, 토큰 검증 실패, 감사 로깅 시 기록되는 구체적인 판정 사유 코드다.
// audit.jsonl 의 reason 필드 및 domain.Error 의 원인 식별자로 사용된다.
type Reason string

const (
	// ReasonAuthorized 는 정책 검증을 통과하여 정상 승인되었음을 나타낸다 (ExitSuccess 매핑).
	ReasonAuthorized Reason = "AUTHORIZED"

	// ReasonNoActiveGrant 는 대상 요청에 일치하는 활성 Grant가 존재하지 않음을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonNoActiveGrant Reason = "NO_ACTIVE_GRANT"

	// ReasonGrantRevoked 는 Grant가 명시적으로 회수(revoked)되었음을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonGrantRevoked Reason = "GRANT_REVOKED"

	// ReasonSubjectEpochRevoked 는 Subject의 Security Epoch가 증가하여 이전 토큰/권한이 일괄 무효화되었음을 나타낸다.
	// 위임 계보(ActorClaim) 연쇄 회수 시에도 발생한다 (ExitAuthzDenied 매핑).
	ReasonSubjectEpochRevoked Reason = "SUBJECT_EPOCH_REVOKED"

	// ReasonTokenInsufficientScope 는 토큰의 스코프가 요청된 액션 및 리소스를 충족하지 못함을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonTokenInsufficientScope Reason = "TOKEN_INSUFFICIENT_SCOPE"

	// ReasonPathViolation 은 지정된 리소스 경로가 허용된 샌드박스/격리 영역을 벗어남을 나타낸다 (ExitPathViolation 매핑).
	ReasonPathViolation Reason = "PATH_VIOLATION"

	// ReasonPathTraversal 은 ../ 또는 절대 경로 순회 시도를 나타낸다 (ExitPathViolation 매핑).
	ReasonPathTraversal Reason = "PATH_TRAVERSAL"

	// ReasonSymlinkEscape 는 심볼릭 링크를 통한 샌드박스 외부 접근 시도를 나타낸다 (ExitPathViolation 매핑).
	ReasonSymlinkEscape Reason = "SYMLINK_ESCAPE"

	// ReasonInvalidPath 는 널 바이트 등 경로 문자열 결함을 나타낸다 (ExitPathViolation 매핑).
	ReasonInvalidPath Reason = "INVALID_PATH"

	// ReasonInvalidToken 은 토큰이 만료되었거나 서명이 유효하지 않음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonInvalidToken Reason = "INVALID_TOKEN"

	// ReasonAuthnUnknownClient 는 등록되지 않은 client_id로 인증을 시도했음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonAuthnUnknownClient Reason = "AUTHN_UNKNOWN_CLIENT"

	// ReasonAuthnInvalidSecret 은 클라이언트 secret이 일치하지 않음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonAuthnInvalidSecret Reason = "AUTHN_INVALID_SECRET"

	// ReasonAuthnClientSuspended 는 정지 또는 비활성화된 클라이언트임을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonAuthnClientSuspended Reason = "AUTHN_CLIENT_SUSPENDED"

	// ReasonTokenInvalidType 은 토큰 헤더의 typ이 at+jwt가 아님을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenInvalidType Reason = "TOKEN_INVALID_TYPE"

	// ReasonTokenAlgNotAllowed 는 허용되지 않은 서명 알고리즘(alg: none 또는 EdDSA 외)임을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenAlgNotAllowed Reason = "TOKEN_ALG_NOT_ALLOWED"

	// ReasonTokenExpired 는 토큰의 exp(만료 시각)가 경과했음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenExpired Reason = "TOKEN_EXPIRED"

	// ReasonTokenNotYetValid 는 토큰의 nbf(유효 시작 시각)에 도달하지 않았음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenNotYetValid Reason = "TOKEN_NOT_YET_VALID"

	// ReasonTokenInvalidIssAud 는 iss 또는 aud 클레임이 기대값과 일치하지 않음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenInvalidIssAud Reason = "TOKEN_INVALID_ISS_AUD"

	// ReasonTokenSubjectMismatch 는 sub 클레임이 기대값과 일치하지 않음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenSubjectMismatch Reason = "TOKEN_SUBJECT_MISMATCH"

	// ReasonTokenReplayDetected 는 이미 소비된 jti를 재사용한 공격임을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenReplayDetected Reason = "TOKEN_REPLAY_DETECTED"

	// ReasonTokenMalformed 는 JWT 구조가 3단 점 분리 형태가 아니거나 JSON 역직렬화에 실패했음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenMalformed Reason = "TOKEN_MALFORMED"

	// ReasonTokenKeyRetired 는 서명에 사용된 키가 폐기(retired)되어 검증 거부됨을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenKeyRetired Reason = "TOKEN_KEY_RETIRED"

	// ReasonTokenKeyNotFound 는 토큰 kid에 일치하는 공개키가 JWKS에 존재하지 않음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenKeyNotFound Reason = "TOKEN_KEY_NOT_FOUND"

	// ReasonTokenInvalidSignature 는 토큰의 암호학적 디지털 서명이 일치하지 않음을 나타낸다 (ExitTokenInvalid 매핑).
	ReasonTokenInvalidSignature Reason = "TOKEN_INVALID_SIGNATURE"

	// ReasonDelegationScopeExceeded 는 자식 토큰의 스코프가 부모 토큰의 스코프 부분집합을 초과함을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonDelegationScopeExceeded Reason = "DELEGATION_SCOPE_EXCEEDED"

	// ReasonDelegationTTLExceeded 는 자식 토큰의 만료시각이 부모 토큰 잔여 유효시간(exp)을 초과함을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonDelegationTTLExceeded Reason = "DELEGATION_TTL_EXCEEDED"

	// ReasonDelegationDepthExceeded 는 위임 체인 허용 최대 깊이를 초과함을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonDelegationDepthExceeded Reason = "DELEGATION_DEPTH_EXCEEDED"

	// ReasonDelegationSelfLoop 는 부모 주체와 자식 주체가 동일하거나 act 계보에 이미 존재하는 순환 위임임을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonDelegationSelfLoop Reason = "DELEGATION_SELF_LOOP"

	// ReasonDelegationScopeEmpty 는 위임 요청 시 요청 스코프가 비어있음을 나타낸다 (ExitBadInput 매핑).
	ReasonDelegationScopeEmpty Reason = "DELEGATION_SCOPE_EMPTY"

	// ReasonDelegationBudgetExceeded 는 자식 예산이 부모 잔여 예산을 초과하거나 부모 예산 엔트리가 없음을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonDelegationBudgetExceeded Reason = "DELEGATION_BUDGET_EXCEEDED"

	// ReasonBudgetExhausted 는 토큰의 호출 횟수·읽기·쓰기 바이트 예산이 소진되었음을 나타낸다 (ExitAuthzDenied 매핑).
	ReasonBudgetExhausted Reason = "BUDGET_EXHAUSTED"

	// ReasonInvalidArguments 는 요청 인자(Action, Resource 등)가 비어있거나 유효하지 않음을 나타낸다 (ExitBadInput 매핑).
	ReasonInvalidArguments Reason = "INVALID_ARGUMENTS"

	// ReasonAuditLogFailed 는 감사 기록(audit.Writer) 실패로 인해 안전 거부되었음을 나타낸다 (ExitAuditFailure 매핑).
	ReasonAuditLogFailed Reason = "AUDIT_LOG_FAILED"

	// ReasonMissingTraceContext 는 요청에 필수 추적 컨텍스트(trace_id)가 누락되었음을 나타낸다 (ExitBadInput 매핑).
	ReasonMissingTraceContext Reason = "MISSING_TRACE_CONTEXT"

	// ReasonAuditIntegrityBroken 은 감사 로그 해시 체인 무결성이 훼손되었음을 나타낸다 (ExitAuditFailure 매핑).
	ReasonAuditIntegrityBroken Reason = "AUDIT_INTEGRITY_BROKEN"

	// ReasonAuditTailIncomplete 는 감사 파일의 마지막 줄이 줄바꿈 없이 잘렸고 그 앞 사슬은 온전함(기록 도중 충돌)을 나타낸다.
	ReasonAuditTailIncomplete Reason = "AUDIT_TAIL_INCOMPLETE"

	// ReasonAuditTruncationDetected 는 서명 체크포인트보다 감사 기록이 짧아졌음(꼬리 절단·삭제)을 나타낸다.
	ReasonAuditTruncationDetected Reason = "AUDIT_TRUNCATION_DETECTED"

	// ReasonAuditCheckpointMismatch 는 서명 체크포인트가 없거나 위조되었거나 기록과 맞지 않음을 나타낸다.
	ReasonAuditCheckpointMismatch Reason = "AUDIT_CHECKPOINT_MISMATCH"

	// ReasonApprovalRequired 는 사람 승인이 필요하나 유효한 승인이 없음(ask)을 나타낸다 (ExitApprovalRequired 매핑).
	ReasonApprovalRequired Reason = "APPROVAL_REQUIRED"

	// ReasonApprovalExpired 는 바인딩은 맞는 승인이 있으나 TTL 이 지났음을 나타낸다 (ExitApprovalRequired 매핑).
	ReasonApprovalExpired Reason = "APPROVAL_EXPIRED"

	// ReasonApprovalMismatch 는 같은 주체의 승인이 있으나 액션·리소스·jti·인자 지문이 맞지 않음을 나타낸다 (ExitApprovalRequired 매핑).
	ReasonApprovalMismatch Reason = "APPROVAL_MISMATCH"

	// ReasonEgressDenied 는 루프백 allow-list 밖 URL·우회 표기·리다이렉트 등 egress 거부를 나타낸다 (ExitPathViolation 매핑).
	ReasonEgressDenied Reason = "EGRESS_DENIED"

	// ReasonExecNotAllowed 는 등록되지 않았거나 형식이 틀린 실행 ID 를 나타낸다 (ExitBadInput 매핑).
	ReasonExecNotAllowed Reason = "EXEC_NOT_ALLOWED"

	// ReasonExecArgRejected 는 실행 인자 형식 위반을 나타낸다 (ExitBadInput 매핑).
	ReasonExecArgRejected Reason = "EXEC_ARG_REJECTED"

	// ReasonToolLimitExceeded 는 가드 자체의 응답·출력·시간 상한 초과를 나타낸다 (ExitInternalError 매핑).
	ReasonToolLimitExceeded Reason = "TOOL_LIMIT_EXCEEDED"

	// ReasonInternalError 는 시스템 예외, I/O 실패 등 내부 복구 불가능 오류를 나타낸다 (ExitInternalError 매핑).
	ReasonInternalError Reason = "INTERNAL_ERROR"

	// ReasonResourceTimeout 은 부모가 강제한 실행 시간 한계 초과를 나타낸다 (ExitResourceLimit 매핑).
	ReasonResourceTimeout Reason = "RESOURCE_TIMEOUT"

	// ReasonResourceOutputLimit 은 부모가 강제한 출력 바이트 한계 초과를 나타낸다 (ExitResourceLimit 매핑).
	ReasonResourceOutputLimit Reason = "RESOURCE_OUTPUT_LIMIT"

	// ReasonSubprocessAbnormalExit 는 원인을 알 수 없는 자식 비정상 종료를 나타낸다 (ExitInternalError 매핑).
	ReasonSubprocessAbnormalExit Reason = "SUBPROCESS_ABNORMAL_EXIT"

	// ReasonConfinementUnavailable 은 격리 필수 모드에서 OS 격리를 적용할 수 없어 스폰이 거부되었음을 나타낸다 (ExitInternalError 매핑).
	ReasonConfinementUnavailable Reason = "CONFINEMENT_UNAVAILABLE"
)
