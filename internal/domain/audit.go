// Package domain 은 SHA-256 해시 체인 기반 감사 로그(audit.jsonl) 불변 레코드 스키마 및 감사 작성기 DIP 포트를 정의한다.
//
// [감사 로그 아키텍처와 ADR 0009 v4 스키마]
// 1. 단방향 SHA-256 해시 사슬 (Hash Chain):
//    - 각 감사 레코드는 이전 레코드의 해시(PrevHash)를 포함하여 자신의 해시(CurrHash)를 계산함으로써,
//      로그 중간 삽입, 삭제, 위변조를 암호학적으로 즉각 탐지할 수 있다.
// 2. 단계(Stage) 필드 보호 (SchemaVersion 4 / ADR 0009):
//    - PEP 10단계 검문소(StageInput ~ StageSettle) 및 토큰 교환소 8단계의 공식 식별자를 Stage 필드에 각인하여
//      인가 파이프라인의 어느 검문소에서 이벤트가 발생했는지 영구 증적을 남긴다.
// 3. Zero Leakage 원칙:
//    - 서명된 원시 JWT 토큰이나 도구 인자 원문은 절대 기록하지 않으며, 토큰은 JTI 로, 인자는 ArgHash(DataDigest)로 대체한다.
package domain

import "time"

// AuditEvent 는 감사 로그(audit.jsonl) 해시 체인에 기록되는 불변의 영속 보안 증거 레코드 스키마다.
type AuditEvent struct {
	// SchemaVersion 은 해시 체인 직렬화 스키마 버전이다.
	// 0/1: 레거시 v1, 2: 확장 필드 보호, 3: 길이 접두 해시 입력(ADR 0006), 4: 단계(stage) 보호(ADR 0009).
	SchemaVersion int `json:"schema_version,omitempty"`

	// Timestamp 는 이벤트 발생 시각(UTC)이다.
	Timestamp time.Time `json:"timestamp"`

	// TraceID 는 분산 추적 및 요청 상관관계(Correlation)를 위한 전역 고유 식별자다.
	TraceID string `json:"trace_id"`

	// Step 은 레거시 단계 명칭이다 (v4 에서는 Stage 필드로 대체 권장).
	Step string `json:"step,omitempty"`

	// Stage 는 파이프라인의 공식 단계 식별자다 (domain.StageInput, domain.StageAuthn 등).
	Stage string `json:"stage,omitempty"`

	// Actor 는 요청을 발생시킨 주체 또는 클라이언트 식별자다.
	Actor string `json:"actor"`

	// AgentID 는 서브에이전트 환경에서 실제 동작을 수행한 에이전트 식별자다.
	AgentID string `json:"agent_id,omitempty"`

	// Action 은 수행하려는 도구 행위다 (file:read, file:write, net:fetch, exec:run).
	Action string `json:"action,omitempty"`

	// Resource 는 대상 리소스 식별자 또는 파일 경로다.
	Resource string `json:"resource,omitempty"`

	// Decision 은 인가 결정 결과다 ("allow", "deny" - 소문자 정규화).
	Decision string `json:"decision,omitempty"`

	// Reason 은 domain.Reason 에 정의된 공식 판정 사유 코드다 (예: AUTHORIZED, TOKEN_EXPIRED).
	Reason string `json:"reason,omitempty"`

	// TokenJTI 는 요청에 사용된 JWT 의 고유 식별자(jti)다 (원시 토큰 대신 기록).
	TokenJTI string `json:"token_jti,omitempty"`

	// ArgHash 는 도구 입력 인자의 SHA-256 지문이다 (domain.DataDigest).
	ArgHash string `json:"arg_hash,omitempty"`

	// ResultHash 는 도구 실행 결과의 SHA-256 지문이다 (domain.DataDigest).
	ResultHash string `json:"result_hash,omitempty"`

	// Success 는 작업이 성공적으로 완수되었는지 여부다.
	Success bool `json:"success"`

	// ErrorClass 는 발생한 오류의 분류 카테고리다.
	ErrorClass string `json:"error_class,omitempty"`

	// PrevHash 는 직전 감사 레코드의 SHA-256 해시값이다 (사슬의 첫 레코드는 Genesis 해시).
	PrevHash string `json:"prev_hash,omitempty"`

	// CurrHash 는 이전 해시와 현재 레코드 필드들을 조합하여 계산된 단방향 해시값이다.
	CurrHash string `json:"curr_hash,omitempty"`

	// Metadata 는 추가적인 디버깅/보안 속성을 담는 보조 맵이다.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AuditWriter 는 감사 로그를 Append-only 방식으로 기록하는 도메인 포트 인터페이스(DIP)다.
// 상위 비즈니스 로직(PEP, PDP, Token 등)은 파일 I/O 나 JSONL 포맷을 몰라도 이 포트를 통해 이벤트를 기록한다.
type AuditWriter interface {
	Log(event AuditEvent) error
	Close() error
}

// EffectivePrevHash 는 최상위 PrevHash 필드값을 반환하며, 레거시 호환성을 위해 없으면 Metadata["prev_hash"] 를 조회한다.
func (e AuditEvent) EffectivePrevHash() string {
	if e.PrevHash != "" {
		return e.PrevHash
	}
	h, _ := e.Metadata["prev_hash"].(string)
	return h
}

// EffectiveCurrHash 는 최상위 CurrHash 필드값을 반환하며, 레거시 호환성을 위해 없으면 Metadata["curr_hash"] 를 조회한다.
func (e AuditEvent) EffectiveCurrHash() string {
	if e.CurrHash != "" {
		return e.CurrHash
	}
	h, _ := e.Metadata["curr_hash"].(string)
	return h
}
