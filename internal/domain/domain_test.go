package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestGrant_Validate(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name    string
		grant   Grant
		wantErr error
	}{
		{
			name: "정상 활성 Grant",
			grant: Grant{
				ID:        "grant-001",
				Subject:   "worker-01",
				Action:    ActionFileRead,
				Resource:  "docs/plan.txt",
				Status:    GrantStatusActive,
				CreatedAt: now,
			},
			wantErr: nil,
		},
		{
			name: "정상 회수된 Grant",
			grant: Grant{
				ID:        "grant-002",
				Subject:   "worker-01",
				Action:    ActionFileWrite,
				Resource:  "data/result.json",
				Status:    GrantStatusRevoked,
				CreatedAt: now,
				RevokedAt: &now,
			},
			wantErr: nil,
		},
		{
			name: "ID 누락 실패",
			grant: Grant{
				ID:        "",
				Subject:   "worker-01",
				Action:    ActionFileRead,
				Resource:  "docs/plan.txt",
				Status:    GrantStatusActive,
				CreatedAt: now,
			},
			wantErr: ErrEmptyGrantID,
		},
		{
			name: "Subject 누락 실패",
			grant: Grant{
				ID:        "grant-001",
				Subject:   "",
				Action:    ActionFileRead,
				Resource:  "docs/plan.txt",
				Status:    GrantStatusActive,
				CreatedAt: now,
			},
			wantErr: ErrEmptySubject,
		},
		{
			name: "Action 누락 실패",
			grant: Grant{
				ID:        "grant-001",
				Subject:   "worker-01",
				Action:    "",
				Resource:  "docs/plan.txt",
				Status:    GrantStatusActive,
				CreatedAt: now,
			},
			wantErr: ErrEmptyAction,
		},
		{
			name: "Resource 누락 실패",
			grant: Grant{
				ID:        "grant-001",
				Subject:   "worker-01",
				Action:    ActionFileRead,
				Resource:  "",
				Status:    GrantStatusActive,
				CreatedAt: now,
			},
			wantErr: ErrEmptyResource,
		},
		{
			name: "경로 순회 탈출 시도 실패",
			grant: Grant{
				ID:        "grant-001",
				Subject:   "worker-01",
				Action:    ActionFileRead,
				Resource:  "../../etc/passwd",
				Status:    GrantStatusActive,
				CreatedAt: now,
			},
			wantErr: ErrRelativeEscape,
		},
		{
			name: "잘못된 상태값 실패",
			grant: Grant{
				ID:        "grant-001",
				Subject:   "worker-01",
				Action:    ActionFileRead,
				Resource:  "docs/plan.txt",
				Status:    "unknown_status",
				CreatedAt: now,
			},
			wantErr: ErrInvalidStatus,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.grant.Validate()
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Fatalf("기대 에러 %v, 실제 결과 %v", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("예상치 못한 에러 발생: %v", err)
				}
			}
		})
	}
}

func TestGrant_Revoke_And_IsActive(t *testing.T) {
	now := time.Now().UTC()
	g := Grant{
		ID:        "grant-100",
		Subject:   "worker-01",
		Action:    ActionFileRead,
		Resource:  "docs/plan.txt",
		Status:    GrantStatusActive,
		CreatedAt: now,
	}

	if !g.IsActive() {
		t.Fatal("초기 상태는 active 여야 합니다")
	}

	revokeTime := now.Add(time.Minute)
	g.Revoke(revokeTime)

	if g.IsActive() {
		t.Fatal("회수 후에는 IsActive가 false여야 합니다")
	}
	if g.Status != GrantStatusRevoked {
		t.Fatalf("기대 상태 %s, 실제 상태 %s", GrantStatusRevoked, g.Status)
	}
	if g.RevokedAt == nil || !g.RevokedAt.Equal(revokeTime) {
		t.Fatalf("회수 시각이 올바르게 기록되지 않았습니다: %v", g.RevokedAt)
	}
}

func TestSecurityEpochs_GetAndBump(t *testing.T) {
	var epochs SecurityEpochs
	// nil 맵 조회 시 기본값 1 반환
	if got := epochs.Get("worker-01"); got != 1 {
		t.Fatalf("nil epochs는 기본값 1을 반환해야 합니다: got %d", got)
	}

	epochs = make(SecurityEpochs)
	// 미등록 주체 기본값 1 반환
	if got := epochs.Get("worker-01"); got != 1 {
		t.Fatalf("미등록 주체는 기본값 1을 반환해야 합니다: got %d", got)
	}

	// Bump 1 -> 2
	next := epochs.Bump("worker-01")
	if next != 2 {
		t.Fatalf("Bump 후 Epoch는 2여야 합니다: got %d", next)
	}
	if got := epochs.Get("worker-01"); got != 2 {
		t.Fatalf("Get 조회 결과는 2여야 합니다: got %d", got)
	}

	// 다른 주체는 여전히 1
	if got := epochs.Get("worker-02"); got != 1 {
		t.Fatalf("다른 주체 worker-02는 기본값 1이어야 합니다: got %d", got)
	}
}

func TestGrant_JSONSerialization(t *testing.T) {
	now := time.Date(2026, 11, 1, 18, 0, 0, 0, time.UTC)
	g := Grant{
		ID:        "grant-550e8400-e29b-41d4-a716-446655440000",
		Subject:   "worker-01",
		Action:    ActionFileRead,
		Resource:  "docs/plan.txt",
		Status:    GrantStatusActive,
		CreatedAt: now,
		RevokedAt: nil,
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("JSON Marshal 실패: %v", err)
	}

	var decoded Grant
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON Unmarshal 실패: %v", err)
	}

	if decoded.ID != g.ID || decoded.Subject != g.Subject || decoded.Action != g.Action ||
		decoded.Resource != g.Resource || decoded.Status != g.Status || !decoded.CreatedAt.Equal(g.CreatedAt) ||
		decoded.RevokedAt != nil {
		t.Fatalf("역직렬화 결과 불일치: %+v", decoded)
	}
}
