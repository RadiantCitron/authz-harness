package pap_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// seedGrant 는 감사 기록 없이 서류철에 Grant 를 직접 넣는다 (시험 준비용).
func seedGrant(t *testing.T, st state.Store, sub string, act domain.Action, res string, requiresApproval bool, status domain.GrantStatus) {
	t.Helper()
	if err := st.Update(func(s *state.GrantsState) error {
		s.Grants = append(s.Grants, domain.Grant{
			ID:               "seed-" + sub + "-" + string(act) + "-" + res,
			Subject:          sub,
			Action:           act,
			Resource:         res,
			Status:           status,
			CreatedAt:        time.Now().UTC(),
			RequiresApproval: requiresApproval,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// 계획 052 M5~M10 (ADR 0011 D-4): 승인은 사람 승인이 필요한 활성 Grant 가 있을 때만 발급된다.
func TestCreateApproval_RequiresApprovalGrant(t *testing.T) {
	req := pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "s.txt", TokenJTI: "j1"}
	cases := []struct {
		name       string
		seed       func(*testing.T, state.Store)
		req        pap.CreateApprovalRequest
		wantReason domain.Reason // 빈 값이면 성공
	}{
		{"M5 승인 필요 활성 허가 있음", func(t *testing.T, st state.Store) {
			seedGrant(t, st, "w", domain.ActionFileWrite, "s.txt", true, domain.GrantStatusActive)
		}, req, ""},
		{"M6 허가 없음", func(*testing.T, state.Store) {}, req, domain.ReasonNoActiveGrant},
		{"M7 승인이 필요 없는 허가만 있음", func(t *testing.T, st state.Store) {
			seedGrant(t, st, "w", domain.ActionFileWrite, "s.txt", false, domain.GrantStatusActive)
		}, req, domain.ReasonInvalidArguments},
		{"M8 회수된 허가만 있음", func(t *testing.T, st state.Store) {
			seedGrant(t, st, "w", domain.ActionFileWrite, "s.txt", true, domain.GrantStatusRevoked)
		}, req, domain.ReasonNoActiveGrant},
		{"M9 다른 대상의 허가만 있음", func(t *testing.T, st state.Store) {
			seedGrant(t, st, "w", domain.ActionFileWrite, "other.txt", true, domain.GrantStatusActive)
		}, req, domain.ReasonNoActiveGrant},
		{"M10 등록되지 않은 행위는 허가 검사보다 먼저 입력 오류", func(*testing.T, state.Store) {},
			pap.CreateApprovalRequest{Subject: "w", Action: "typo", Resource: "s.txt", TokenJTI: "j1"}, domain.ReasonInvalidArguments},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, statePath, auditPath := setupTestPAP(t)
			st := mustStore(t, statePath)
			c.seed(t, st)

			_, err := svc.CreateApproval(context.Background(), c.req)
			loaded, lerr := st.Load()
			if lerr != nil {
				t.Fatal(lerr)
			}
			raw, _ := os.ReadFile(auditPath)
			if c.wantReason == "" {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				if len(loaded.Approvals) != 1 || !strings.Contains(string(raw), "approval.granted") {
					t.Fatalf("approval must be stored and audited: %d approvals", len(loaded.Approvals))
				}
				return
			}
			if got := domain.ReasonFromError(err, ""); got != c.wantReason {
				t.Fatalf("reason = %q, want %q (err=%v)", got, c.wantReason, err)
			}
			if len(loaded.Approvals) != 0 {
				t.Fatalf("ledger must be unchanged, got %d approvals", len(loaded.Approvals))
			}
			if strings.Contains(string(raw), "approval.granted") {
				t.Fatal("approval.granted must not be recorded on rejection")
			}
			if !strings.Contains(string(raw), "approval.create.deny") {
				t.Fatal("approval.create.deny must be recorded")
			}
		})
	}
}
