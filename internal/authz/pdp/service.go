// Package pdp 는 인가 결정 지점(Policy Decision Point)으로서 인가 요청(Request)에 대해 허용(ALLOW), 거부(DENY), 또는 사람 승인 대기(ASK)를 판정하는 두뇌 역할을 수행한다.
//
// [핵심 아키텍처 원칙 및 보안 불변식]
// 1. I/O 배제 및 순수 함수 원칙 (Zero I/O / Pure Function):
//   - Evaluate(req, snapshot) 는 파일, 네트워크, OS 시스템 콜, OS 시계(time.Now)를 일체 호출하지 않는 순수 함수다.
//   - 모든 판단에 필요한 상태는 PIP(Policy Information Point)가 사전에 조립한 domain.SubjectSnapshot 으로부터 공급받는다.
//   - 아키텍처 가드레일 TC-060-01 에 의해 os, net, io, confinement 등의 import 가 엄격히 차단된다.
//
// 2. Security Epoch 연쇄 검증 (Lineage Epoch Verification):
//   - 주체의 Epoch 뿐만 아니라 위임 조상(act 사슬) 전체의 Epoch 를 snapshot.ValidateLineageEpoch 를 통해 단일 트랜잭션으로 검증한다.
//   - 상위 오케스트레이터의 세대가 갱신되면 하위 서브에이전트에게 위임된 토큰도 연쇄적으로 즉시 무효화된다 (연쇄 회수).
//
// 3. 3대 판정 유형 (ALLOW / DENY / ASK):
//   - DecisionAllow: 활성 Grant 가 존재하고 human approval 이 불필요하거나 유효한 Approval 이 바인딩된 경우.
//   - DecisionAsk: 권한은 부여되어 있으나 위험 작업이어서 사람 승인이 필요한 경우 (PEP approval 단계에서 사람 승인 검사).
//   - DecisionDeny: 일치하는 활성 권한이 없거나, 만료/회수되었거나, 스코프가 부족하거나, Epoch 가 불일치하는 경우.
//
// 4. DIP(의존성 역전 원칙) 배선:
//   - internal/app/builder.go 의 BuildStack 에서 pip.NewService 와 audit.Writer 를 주입받아 조립된다.
package pdp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authz-harness/internal/domain"
)

// DecisionType 은 인가 판정의 최종 결과(허용/거부/승인대기)를 나타내는 열거형 타입이다.
type DecisionType string

const (
	// DecisionAllow 는 요청된 작업이 정책 및 활성 권한에 부합하여 즉시 실행 허용됨을 의미한다.
	DecisionAllow DecisionType = "ALLOW"

	// DecisionDeny 는 요청된 작업이 권한 부재, 회수, 스코프 부족 등으로 거부됨을 의미한다.
	DecisionDeny DecisionType = "DENY"

	// DecisionAsk 는 허용 권한은 존재하나 고위험 작업으로 분류되어 사전에 사람 승인(Approval)이 필요함을 뜻한다.
	// 유효한 승인이 바인딩되어 있지 않으면 거부(DENY)와 동일하게 처리된다.
	DecisionAsk DecisionType = "ASK"
)

// Request 는 PDP 인가 결정을 위한 단일 요청 명세다.
type Request struct {
	// Subject 는 작업을 수행하려는 주체 식별자다 (예: "worker-01").
	Subject string `json:"subject"`

	// Action 은 수행하려는 도구 액션이다 (예: "file:read", "exec:run").
	Action domain.Action `json:"action"`

	// Resource 는 대상 리소스 경로 또는 식별자다 (예: "tasks.txt").
	Resource string `json:"resource"`

	// Epoch 는 요청자가 제시한 토큰의 보안 세대 번호다 (기본값 1).
	Epoch domain.Epoch `json:"epoch"`

	// TokenScope 는 제시된 Bearer 토큰의 인가 스코프 문자열이다.
	TokenScope string `json:"token_scope,omitempty"`

	// RequireScope 가 true 면 TokenScope 가 비어있을 경우 즉시 거부한다.
	RequireScope bool `json:"require_scope,omitempty"`

	// Actor 는 토큰 위임 계보(RFC 8693)를 나타내는 선대 부모 주체 사슬이다.
	Actor *domain.ActorClaim `json:"actor,omitempty"`

	// TraceID 는 분산 감사 추적을 위한 고유 식별자다.
	TraceID string `json:"trace_id,omitempty"`

	// TokenJTI 는 요청에 사용된 토큰 고유 식별자(JTI)다 (승인 바인딩 검증용).
	TokenJTI string `json:"token_jti,omitempty"`

	// ArgHash 는 실행 인자의 SHA-256 해시값이다 (정밀 승인 바인딩용).
	ArgHash string `json:"arg_hash,omitempty"`

	// Now 는 판정에 사용할 기준 시각이다. 비어있으면 snapshot.Timestamp 를 사용한다.
	// PDP 는 순수 함수성을 위해 자체적으로 time.Now() 시스템 콜을 호출하지 않는다.
	Now time.Time `json:"now,omitempty"`
}

// Decision 은 PDP 의 판정 결과 및 상세 사유 구조체다.
type Decision struct {
	// Decision 은 최종 판정 결과 (ALLOW, DENY, ASK) 다.
	Decision DecisionType `json:"decision"`

	// Reason 은 표준화된 도메인 사유 코드다 (예: AUTHORIZED, NO_ACTIVE_GRANT, TOKEN_INSUFFICIENT_SCOPE).
	Reason domain.Reason `json:"reason"`

	// GrantID 는 판정에 매칭된 활성 Grant 의 고유 식별자다.
	GrantID string `json:"grant_id,omitempty"`

	// Details 는 판정 사유에 대한 상세 설명 문구다.
	Details string `json:"details,omitempty"`

	// ApprovalID 는 승인 기반 ALLOW 판정 시 소비 대상이 되는 승인(Approval)의 ID 다.
	ApprovalID string `json:"approval_id,omitempty"`
}

// Evaluate 는 일체의 부작용 없이 순수 인자만을 대조하여 인가 여부를 결정하는 순수 함수다.
// 도메인 SubjectSnapshot 과 요청(Request)만을 대조하며 파일 I/O 나 OS 호출을 일체 수행하지 않는다.
func Evaluate(req Request, snapshot *domain.SubjectSnapshot) Decision {
	cleanSub := strings.TrimSpace(req.Subject)
	cleanRes := strings.TrimSpace(req.Resource)

	// 1. 입력 무결성 검증 (Fail-Closed)
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

	// 2. Security Epoch 일치 검증 및 위임 계보(act 사슬) 연쇄 Epoch 검증 (도메인 SSOT)
	if reason, badAncestor := snapshot.ValidateLineageEpoch(cleanSub, req.Epoch, req.Actor); reason != "" {
		details := "Security Epoch 가 현재 활성 Epoch 와 일치하지 않아 무효화되었습니다."
		if badAncestor != nil {
			details = fmt.Sprintf("위임 조상 %q의 제시 Epoch(%d)가 현재 Epoch(%d)와 일치하지 않아 하위 위임 토큰이 무효화되었습니다.",
				badAncestor.Subject, badAncestor.Epoch, snapshot.SubjectEpochs.Get(badAncestor.Subject))
		} else if req.Actor != nil && snapshot.SubjectEpochs == nil {
			details = "위임 계보 Epoch 정보가 공급되지 않아 조상 Epoch를 검증할 수 없습니다."
		} else if req.Epoch != snapshot.CurrentEpoch {
			details = fmt.Sprintf("제시된 Security Epoch(%d)가 현재 활성 Epoch(%d)와 일치하지 않아 토큰/권한이 무효화되었습니다.", req.Epoch, snapshot.CurrentEpoch)
		}
		return Decision{
			Decision: DecisionDeny,
			Reason:   reason,
			Details:  details,
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
	// 맞는 활성 Grant 를 모두 모은다. 하나라도 승인이 필요하면 가장 엄격한 쪽(NeedsApproval)을 따른다.
	var matched *domain.Grant
	needsApproval := false
	for i := range snapshot.ActiveGrants {
		g := &snapshot.ActiveGrants[i]
		if g.Subject == cleanSub && g.Action == req.Action && g.Resource == cleanRes && g.IsActive() {
			if matched == nil || (g.RequiresApproval && !matched.RequiresApproval) {
				matched = g
			}
			if g.RequiresApproval {
				needsApproval = true
			}
		}
	}
	if matched != nil {
		if !needsApproval {
			return Decision{
				Decision: DecisionAllow,
				Reason:   domain.ReasonAuthorized,
				GrantID:  matched.ID,
				Details:  fmt.Sprintf("활성 권한(%s)에 의해 정상 인가되었습니다.", matched.ID),
			}
		}
		now := req.Now
		if now.IsZero() {
			now = snapshot.Timestamp
		}
		id, reason := domain.SelectApproval(snapshot.Approvals, domain.ApprovalBinding{
			Subject: cleanSub, Action: req.Action, Resource: cleanRes, TokenJTI: req.TokenJTI, ArgHash: req.ArgHash,
		}, now)
		if reason == domain.ReasonAuthorized {
			return Decision{
				Decision:   DecisionAllow,
				Reason:     domain.ReasonAuthorized,
				GrantID:    matched.ID,
				ApprovalID: id,
				Details:    fmt.Sprintf("활성 권한(%s)과 승인(%s)에 의해 정상 인가되었습니다.", matched.ID, id),
			}
		}
		return Decision{
			Decision: DecisionAsk,
			Reason:   reason,
			GrantID:  matched.ID,
			Details:  fmt.Sprintf("권한(%s)은 사람 승인이 필요하며 유효한 승인이 없습니다(%s).", matched.ID, reason),
		}
	}

	// 5. 회수된 Grant 이력 검증 (GRANT_REVOKED 명시 판정)
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

// EvaluatorFunc 는 요청과 주체 스냅샷만으로 인가 결정을 계산하는 순수 평가 함수 타입이다.
// 기본값은 패키지 순수 함수 Evaluate 이며, WithEvaluator 옵션으로 커스텀 정책 함수나 외부 정책 엔진 어댑터를 주입할 수 있다.
type EvaluatorFunc func(req Request, snapshot *domain.SubjectSnapshot) Decision

// Service 는 PIP 상태 조회와 감사 로깅을 조율하는 PDP 서비스 규약이다.
type Service interface {
	// Decide 는 PIP 에서 스냅샷을 조회하여 평가하고 결과를 감사 로그에 기록한 후 반환한다.
	Decide(ctx context.Context, req Request) (*Decision, error)
}

// pdpService 는 Service의 표준 구현체다.
type pdpService struct {
	pipSvc domain.SnapshotProvider
	audit  domain.AuditWriter
	clock  domain.Clock
	eval   EvaluatorFunc
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

// WithEvaluator 는 커스텀 순수 평가 함수(또는 외부 정책 엔진 어댑터)를 주입하는 옵션이다.
// nil 이 전달되면 기본 내장 Evaluate 함수를 유지한다.
func WithEvaluator(fn EvaluatorFunc) ServiceOption {
	return func(s *pdpService) {
		if fn != nil {
			s.eval = fn
		}
	}
}

// NewService 는 PIP와 Audit Writer를 주입받아 PDP 서비스를 생성한다.
func NewService(pipSvc domain.SnapshotProvider, audit domain.AuditWriter, opts ...ServiceOption) Service {
	s := &pdpService{
		pipSvc: pipSvc,
		audit:  audit,
		clock:  domain.RealClock{},
		eval:   Evaluate,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Decide 는 주체의 최신 상태 스냅샷을 PIP로부터 조회하고, 순수 평가 함수(eval)로 판정한 뒤
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

	evalFn := s.eval
	if evalFn == nil {
		evalFn = Evaluate
	}
	decision := evalFn(req, snapshot)

	now := s.clock.Now().UTC()
	traceID := req.TraceID

	// 감사 이벤트 기록: Zero Leakage 및 Fail-Closed 원칙 준수
	if s.audit != nil {
		event := domain.AuditEvent{
			Timestamp: now,
			TraceID:   traceID,
			Step:      "pdp.decide",
			Actor:     req.Subject,
			AgentID:   req.Subject,
			Action:    "pdp.decide",
			Resource:  req.Resource,
			Decision:  strings.ToLower(string(decision.Decision)),
			Reason:    string(decision.Reason),
			TokenJTI:  req.TokenJTI,
			ArgHash:   req.ArgHash,
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

		if decision.ApprovalID != "" {
			event.Metadata["approval_id"] = decision.ApprovalID
		}
		if req.Actor != nil && req.Actor.Subject != "" {
			event.Metadata["caller_id"] = req.Actor.Subject
		}

		if err := s.audit.Log(event); err != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "pdp: audit logging failed (fail-closed)", err)
		}
	}

	return &decision, nil
}
