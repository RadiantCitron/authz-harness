package domain

import "time"

// AuditEvent 는 감사 로그(audit.jsonl) 해시 체인에 기록되는 불변의 영속 보안 증거 레코드 스키마다.
type AuditEvent struct {
	SchemaVersion int                    `json:"schema_version,omitempty"` // 0·1: 레거시 v1, 2: 확장 필드 보호, 3: 길이 접두 해시 입력(ADR 0006), 4: 단계(stage) 보호(ADR 0009)
	Timestamp     time.Time              `json:"timestamp"`
	TraceID       string                 `json:"trace_id"`
	Step          string                 `json:"step,omitempty"`
	Stage         string                 `json:"stage,omitempty"` // v4: PEP 파이프라인 단계 ID(ADR 0007). 파이프라인 밖 이벤트는 비운다
	Actor         string                 `json:"actor"`
	AgentID       string                 `json:"agent_id,omitempty"`
	Action        string                 `json:"action,omitempty"`
	Resource      string                 `json:"resource,omitempty"`
	Decision      string                 `json:"decision,omitempty"` // allow, deny (소문자 정규화)
	Reason        string                 `json:"reason,omitempty"`   // domain.Reason 문자열 (최상위 필수 승격)
	TokenJTI      string                 `json:"token_jti,omitempty"`
	ArgHash       string                 `json:"arg_hash,omitempty"`    // v2: 도구 인자 지문(domain.DataDigest)
	ResultHash    string                 `json:"result_hash,omitempty"` // v2: 도구 결과 지문(domain.DataDigest)
	Success       bool                   `json:"success"`
	ErrorClass    string                 `json:"error_class,omitempty"`
	PrevHash      string                 `json:"prev_hash,omitempty"`
	CurrHash      string                 `json:"curr_hash,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// AuditWriter 는 감사 로그를 Append-only 방식으로 기록하는 도메인 포트(DIP)다.
type AuditWriter interface {
	Log(event AuditEvent) error
	Close() error
}
