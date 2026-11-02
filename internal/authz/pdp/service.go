package pdp

import (
	"context"
	"fmt"
	"strings"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/domain"
)

// DecisionType 은 인가 판정의 최종 결과(허용/거부)다.
type DecisionType string

const (
	DecisionAllow DecisionType = "ALLOW"
	DecisionDeny  DecisionType = "DENY"
)

// Request 는 PDP 인가 결정을 위한 단일 요청 명세다.
type Request struct {
	Subject      string             `json:"subject"`
	Action       domain.Action      `json:"action"`
	Resource     string             `json:"resource"`
	Epoch        domain.Epoch       `json:"epoch"` // 요청자가 제시한 Security Epoch (기본값 1)
	TokenScope   string             `json:"token_scope,omitempty"`
	RequireScope bool               `json:"require_scope,omitempty"` // true 인 경우 TokenScope 가 비어있어도 즉시 거부
	Actor        *domain.ActorClaim `json:"actor,omitempty"`
	TraceID      string             `json:"trace_id,omitempty"`
}

// Decision 은 PDP의 판정 결과 및 상세 사유다.
type Decision struct {
	Decision DecisionType  `json:"decision"`
	Reason   domain.Reason `json:"reason"`
	GrantID  string        `json:"grant_id,omitempty"`
	Details  string        `json:"details,omitempty"`
}

// Evaluate 는 일체의 부작용 없이 순수 인자만을 대조하여 인가 여부를 결정하는 순수 함수다.
// Layer 2B의 pip.SubjectSnapshot과 요청(Request)만을 대조하며 파일 I/O나 OS 호출을 일체 수행하지 않는다.
func Evaluate(req Request, snapshot *pip.SubjectSnapshot) Decision {
	cleanSub := strings.TrimSpace(req.Subject)
	cleanRes := strings.TrimSpace(req.Resource)

	// 1. 입력 무결성 검증
	if cleanSub == "" || req.Action == "" || cleanRes == "" || req.Epoch < 1 {
		return Decision{
			Decision: DecisionDeny,
			Reason:   domain.ReasonNoActiveGrant,
			Details:  "유효하지 않거나 누락된 요청 인자입니다.",
		}
	}

	if snapshot == nil {
		return Decision{
			Decision: DecisionDeny,
			Reason:   domain.ReasonNoActiveGrant,
			Details:  "주체 상태 스냅샷을 찾을 수 없습니다.",
		}
	}

	// 2. Security Epoch 일치 검증 (최우선 차단 - 킬스위치)
	if req.Epoch != snapshot.CurrentEpoch {
		return Decision{
			Decision: DecisionDeny,
			Reason:   domain.ReasonSubjectEpochRevoked,
			Details:  fmt.Sprintf("제시된 Security Epoch(%d)가 현재 활성 Epoch(%d)와 일치하지 않아 토큰/권한이 무효화되었습니다.", req.Epoch, snapshot.CurrentEpoch),
		}
	}

	// 3. 토큰 Scope 검증 (Scope가 요구되거나 전달된 경우)
	if req.RequireScope || strings.TrimSpace(req.TokenScope) != "" {
		if !domain.ScopeMatches(req.TokenScope, req.Action, cleanRes) {
			return Decision{
				Decision: DecisionDeny,
				Reason:   domain.ReasonTokenInsufficientScope,
				Details:  fmt.Sprintf("token scope %q does not permit action %s on %s", req.TokenScope, req.Action, cleanRes),
			}
		}
	}

	// 4. 활성 Grant 매칭 검증
	for _, g := range snapshot.ActiveGrants {
		if g.Subject == cleanSub && g.Action == req.Action && g.Resource == cleanRes && g.IsActive() {
			return Decision{
				Decision: DecisionAllow,
				Reason:   domain.ReasonAuthorized,
				GrantID:  g.ID,
				Details:  fmt.Sprintf("활성 권한(%s)에 의해 정상 인가되었습니다.", g.ID),
			}
		}
	}

	// 5. 회수된 Grant 이력 검증
	for _, g := range snapshot.RevokedGrants {
		if g.Subject == cleanSub && g.Action == req.Action && g.Resource == cleanRes {
			return Decision{
				Decision: DecisionDeny,
				Reason:   domain.ReasonGrantRevoked,
				GrantID:  g.ID,
				Details:  fmt.Sprintf("요청된 권한(%s)이 이전에 발급되었으나 명시적으로 회수(Revoked)되었습니다.", g.ID),
			}
		}
	}

	// 6. 기본 거부 (Deny-by-Default / Fail-Closed)
	return Decision{
		Decision: DecisionDeny,
		Reason:   domain.ReasonNoActiveGrant,
		Details:  "일치하는 활성 권한을 찾을 수 없습니다.",
	}
}

// Service 는 PIP 상태 조회와 감사 로깅을 조율하는 PDP 서비스 규약이다.
type Service interface {
	Decide(ctx context.Context, req Request) (*Decision, error)
}

// pdpService 는 Service의 표준 구현체다.
type pdpService struct {
	pipSvc pip.Service
	audit  audit.Writer
	clock  domain.Clock
}

// ServiceOption 은 PDP 서비스 구성 옵션이다.
type ServiceOption func(*pdpService)

// WithClock 은 가상 시계를 주입하기 위한 옵션이다.
func WithClock(c domain.Clock) ServiceOption {
	return func(s *pdpService) {
		if c != nil {
			s.clock = c
		}
	}
}

// NewService 는 PIP와 Audit Writer를 주입받아 PDP 서비스를 생성한다.
func NewService(pipSvc pip.Service, audit audit.Writer, opts ...ServiceOption) Service {
	s := &pdpService{
		pipSvc: pipSvc,
		audit:  audit,
		clock:  domain.RealClock{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Decide 는 주체의 최신 상태 스냅샷을 PIP로부터 조회하고, 순수 Evaluate 함수로 판정한 뒤
// 그 결과를 감사 로그(audit.jsonl)에 기록하고 Decision을 반환한다.
// 감사 기록에 실패할 경우 Fail-Closed 원칙에 따라 에러를 반환한다.
func (s *pdpService) Decide(ctx context.Context, req Request) (*Decision, error) {
	// 기본 Epoch 보정 (미지정 시 1)
	if req.Epoch == 0 {
		req.Epoch = 1
	}

	snapshot, err := s.pipSvc.GetSubjectSnapshot(ctx, req.Subject)
	if err != nil {
		return nil, fmt.Errorf("pdp: failed to query pip snapshot: %w", err)
	}

	decision := Evaluate(req, snapshot)

	now := s.clock.Now().UTC()
	traceID := req.TraceID

	// 도메인 이벤트 수집기가 컨텍스트에 주입된 경우 도메인 사건 기록 (DIP)
	if recorder := domain.EventRecorderFromContext(ctx); recorder != nil {
		recorder.Record(domain.DomainEvent{
			Timestamp: now,
			TraceID:   traceID,
			Stage:     "pdp.decide",
			Actor:     req.Subject,
			Action:    string(req.Action),
			Resource:  req.Resource,
			Decision:  string(decision.Decision),
			Reason:    decision.Reason,
			Success:   decision.Decision == DecisionAllow,
			Metadata: map[string]interface{}{
				"grant_id": decision.GrantID,
				"details":  decision.Details,
			},
		})
	}

	// 감사 이벤트 기록
	if s.audit != nil {
		event := audit.Event{
			Timestamp: now,
			TraceID:   traceID,
			Step:      "pdp.decide",
			Actor:     req.Subject,
			AgentID:   req.Subject,
			Action:    "pdp.decide",
			Resource:  req.Resource,
			Decision:  strings.ToLower(string(decision.Decision)),
			Reason:    string(decision.Reason),
			Success:   decision.Decision == DecisionAllow,
			Metadata: map[string]interface{}{
				"decision":         string(decision.Decision),
				"reason":           string(decision.Reason),
				"subject":          req.Subject,
				"requested_action": string(req.Action),
				"requested_epoch":  int64(req.Epoch),
				"current_epoch":    int64(snapshot.CurrentEpoch),
				"grant_id":         decision.GrantID,
				"details":          decision.Details,
			},
		}

		if req.Actor != nil && req.Actor.Subject != "" {
			event.Metadata["caller_id"] = req.Actor.Subject
		}

		if err := s.audit.Log(event); err != nil {
			return nil, fmt.Errorf("pdp: audit logging failed (fail-closed): %w", err)
		}
	}

	return &decision, nil
}
