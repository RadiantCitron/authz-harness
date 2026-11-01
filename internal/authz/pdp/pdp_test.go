package pdp_test

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/domain"
)

// mockPIP 는 테스트용 PIP 구현체다.
type mockPIP struct {
	snapshot *pip.SubjectSnapshot
	err      error
}

func (m *mockPIP) GetSubjectSnapshot(ctx context.Context, subject string) (*pip.SubjectSnapshot, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.snapshot, nil
}

func (m *mockPIP) GetActiveGrants(ctx context.Context, subject string) ([]domain.Grant, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.snapshot.ActiveGrants, nil
}

func (m *mockPIP) GetCurrentEpoch(ctx context.Context, subject string) (domain.Epoch, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.snapshot.CurrentEpoch, nil
}

// mockAudit 는 테스트용 감사 로거 구현체다.
type mockAudit struct {
	events []audit.Event
	err    error
}

func (m *mockAudit) Log(e audit.Event) error {
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, e)
	return nil
}

func (m *mockAudit) Close() error {
	return nil
}

// TestPDP_StrictNoOSImports 는 AP-03 불변식에 따라 internal/authz/pdp 패키지가
// os, path/filepath, io/fs, internal/jail 패키지를 절대 import하지 않는지 정적으로 검증한다.
func TestPDP_StrictNoOSImports(t *testing.T) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "service.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse service.go: %v", err)
	}

	prohibited := map[string]bool{
		`"os"`:                     true,
		`"path/filepath"`:          true,
		`"io/fs"`:                  true,
		`"authz-harness/internal/jail"`: true,
	}

	for _, imp := range node.Imports {
		pathVal := imp.Path.Value
		if prohibited[pathVal] {
			t.Fatalf("violation of AP-03: pdp package must not import %s", pathVal)
		}
	}
}

// TestPDP_Evaluate_TableDriven 은 L1 결정표에 명시된 모든 판정 케이스를 검증한다.
func TestPDP_Evaluate_TableDriven(t *testing.T) {
	now := time.Now().UTC()

	baseSnapshot := &pip.SubjectSnapshot{
		Subject:      "worker-01",
		CurrentEpoch: 1,
		ActiveGrants: []domain.Grant{
			{
				ID:        "grant-read-01",
				Subject:   "worker-01",
				Action:    domain.ActionFileRead,
				Resource:  "docs/plan.txt",
				Status:    domain.GrantStatusActive,
				CreatedAt: now,
			},
			{
				ID:        "grant-write-01",
				Subject:   "worker-01",
				Action:    domain.ActionFileWrite,
				Resource:  "data/result.txt",
				Status:    domain.GrantStatusActive,
				CreatedAt: now,
			},
		},
		RevokedGrants: []domain.Grant{
			{
				ID:        "grant-read-revoked",
				Subject:   "worker-01",
				Action:    domain.ActionFileRead,
				Resource:  "secret/config.json",
				Status:    domain.GrantStatusRevoked,
				CreatedAt: now,
				RevokedAt: &now,
			},
		},
		Timestamp: now,
	}

	tests := []struct {
		name             string
		req              pdp.Request
		snapshot         *pip.SubjectSnapshot
		expectedDecision pdp.DecisionType
		expectedReason   domain.Reason
		expectedGrantID  string
	}{
		{
			name: "TC-01: 활성 Grant와 일치 시 정상 인가 (ALLOW)",
			req: pdp.Request{
				Subject:  "worker-01",
				Action:   domain.ActionFileRead,
				Resource: "docs/plan.txt",
				Epoch:    1,
			},
			snapshot:         baseSnapshot,
			expectedDecision: pdp.DecisionAllow,
			expectedReason:   domain.ReasonAuthorized,
			expectedGrantID:  "grant-read-01",
		},
		{
			name: "TC-02: 권한이 전혀 없는 리소스 요청 시 NO_ACTIVE_GRANT 거부 (DENY)",
			req: pdp.Request{
				Subject:  "worker-01",
				Action:   domain.ActionFileRead,
				Resource: "other/unknown.txt",
				Epoch:    1,
			},
			snapshot:         baseSnapshot,
			expectedDecision: pdp.DecisionDeny,
			expectedReason:   domain.ReasonNoActiveGrant,
		},
		{
			name: "TC-03: 액션 불일치 시 NO_ACTIVE_GRANT 거부 (DENY)",
			req: pdp.Request{
				Subject:  "worker-01",
				Action:   domain.ActionFileWrite,
				Resource: "docs/plan.txt", // read만 허용되어 있음
				Epoch:    1,
			},
			snapshot:         baseSnapshot,
			expectedDecision: pdp.DecisionDeny,
			expectedReason:   domain.ReasonNoActiveGrant,
		},
		{
			name: "TC-04: 회수된 Grant 요청 시 GRANT_REVOKED 거부 (DENY)",
			req: pdp.Request{
				Subject:  "worker-01",
				Action:   domain.ActionFileRead,
				Resource: "secret/config.json",
				Epoch:    1,
			},
			snapshot:         baseSnapshot,
			expectedDecision: pdp.DecisionDeny,
			expectedReason:   domain.ReasonGrantRevoked,
			expectedGrantID:  "grant-read-revoked",
		},
		{
			name: "TC-05: Security Epoch 불일치 시 SUBJECT_EPOCH_REVOKED 최우선 거부 (DENY)",
			req: pdp.Request{
				Subject:  "worker-01",
				Action:   domain.ActionFileRead,
				Resource: "docs/plan.txt",
				Epoch:    2, // snapshot은 1이므로 불일치
			},
			snapshot:         baseSnapshot,
			expectedDecision: pdp.DecisionDeny,
			expectedReason:   domain.ReasonSubjectEpochRevoked,
		},
		{
			name: "TC-06: 요청 인자 누락 (Subject 공백) 시 거부 (DENY)",
			req: pdp.Request{
				Subject:  "",
				Action:   domain.ActionFileRead,
				Resource: "docs/plan.txt",
				Epoch:    1,
			},
			snapshot:         baseSnapshot,
			expectedDecision: pdp.DecisionDeny,
			expectedReason:   domain.ReasonNoActiveGrant,
		},
		{
			name: "TC-07: 요청 인자 누락 (Epoch < 1) 시 거부 (DENY)",
			req: pdp.Request{
				Subject:  "worker-01",
				Action:   domain.ActionFileRead,
				Resource: "docs/plan.txt",
				Epoch:    0,
			},
			snapshot:         baseSnapshot,
			expectedDecision: pdp.DecisionDeny,
			expectedReason:   domain.ReasonNoActiveGrant,
		},
		{
			name: "TC-08: 스냅샷이 nil인 경우 Fail-Closed 거부 (DENY)",
			req: pdp.Request{
				Subject:  "worker-01",
				Action:   domain.ActionFileRead,
				Resource: "docs/plan.txt",
				Epoch:    1,
			},
			snapshot:         nil,
			expectedDecision: pdp.DecisionDeny,
			expectedReason:   domain.ReasonNoActiveGrant,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := pdp.Evaluate(tc.req, tc.snapshot)
			if dec.Decision != tc.expectedDecision {
				t.Errorf("expected decision %s, got %s", tc.expectedDecision, dec.Decision)
			}
			if dec.Reason != tc.expectedReason {
				t.Errorf("expected reason %s, got %s", tc.expectedReason, dec.Reason)
			}
			if tc.expectedGrantID != "" && dec.GrantID != tc.expectedGrantID {
				t.Errorf("expected grant id %s, got %s", tc.expectedGrantID, dec.GrantID)
			}
		})
	}
}

// TestPDP_Service_Audit_FailClosed 는 감사 로깅 실패 시 인가 결정이 정상 진행되지 않고
// Fail-Closed 원칙에 따라 즉시 에러를 반환하는지 검증한다.
func TestPDP_Service_Audit_FailClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	pipMock := &mockPIP{
		snapshot: &pip.SubjectSnapshot{
			Subject:      "worker-01",
			CurrentEpoch: 1,
			ActiveGrants: []domain.Grant{
				{
					ID:        "grant-01",
					Subject:   "worker-01",
					Action:    domain.ActionFileRead,
					Resource:  "docs/plan.txt",
					Status:    domain.GrantStatusActive,
					CreatedAt: now,
				},
			},
		},
	}

	// 1. 감사 로깅 실패 모의
	auditFail := &mockAudit{err: errors.New("disk full / flock timeout")}
	svc := pdp.NewService(pipMock, auditFail)

	req := pdp.Request{
		Subject:  "worker-01",
		Action:   domain.ActionFileRead,
		Resource: "docs/plan.txt",
		Epoch:    1,
	}

	dec, err := svc.Decide(ctx, req)
	if err == nil {
		t.Fatalf("expected error on audit failure, got nil")
	}
	if dec != nil {
		t.Fatalf("expected nil decision on audit failure, got %+v", dec)
	}

	// 2. 감사 로깅 정상 작동 시 성공 확인
	auditSuccess := &mockAudit{}
	svcOk := pdp.NewService(pipMock, auditSuccess)

	decOk, errOk := svcOk.Decide(ctx, req)
	if errOk != nil {
		t.Fatalf("unexpected error: %v", errOk)
	}
	if decOk.Decision != pdp.DecisionAllow {
		t.Errorf("expected ALLOW, got %s", decOk.Decision)
	}
	if len(auditSuccess.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(auditSuccess.events))
	}
	event := auditSuccess.events[0]
	if event.Action != "pdp.decide" || event.Actor != "worker-01" || !event.Success {
		t.Errorf("unexpected audit event content: %+v", event)
	}
}
