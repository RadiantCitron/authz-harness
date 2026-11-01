package pip_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/authz/pip"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

func setupTestPIP(t *testing.T) (pip.Service, state.Store) {
	t.Helper()
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")

	store, err := state.NewFileStore(statePath)
	if err != nil {
		t.Fatalf("failed to create FileStore: %v", err)
	}

	svc := pip.NewService(store)
	return svc, store
}

func TestPIP_GetSubjectSnapshot(t *testing.T) {
	ctx := context.Background()
	svc, store := setupTestPIP(t)

	// 초기 상태 주입: worker-01 (활성 2건, 회수 1건, Epoch 2), worker-02 (활성 1건)
	now := time.Now().UTC()
	err := store.Update(func(st *state.GrantsState) error {
		st.Epochs["worker-01"] = 2
		st.Grants = append(st.Grants,
			domain.Grant{
				ID:        "grant-1",
				Subject:   "worker-01",
				Action:    domain.ActionFileRead,
				Resource:  "docs/a.txt",
				Status:    domain.GrantStatusActive,
				CreatedAt: now,
			},
			domain.Grant{
				ID:        "grant-2",
				Subject:   "worker-01",
				Action:    domain.ActionFileWrite,
				Resource:  "docs/b.txt",
				Status:    domain.GrantStatusRevoked,
				CreatedAt: now,
				RevokedAt: &now,
			},
			domain.Grant{
				ID:        "grant-3",
				Subject:   "worker-01",
				Action:    domain.ActionFileRead,
				Resource:  "docs/c.txt",
				Status:    domain.GrantStatusActive,
				CreatedAt: now,
			},
			domain.Grant{
				ID:        "grant-4",
				Subject:   "worker-02",
				Action:    domain.ActionFileRead,
				Resource:  "docs/other.txt",
				Status:    domain.GrantStatusActive,
				CreatedAt: now,
			},
		)
		return nil
	})
	if err != nil {
		t.Fatalf("store update failed: %v", err)
	}

	// 1. worker-01 스냅샷 검증
	snapshot, err := svc.GetSubjectSnapshot(ctx, "worker-01")
	if err != nil {
		t.Fatalf("GetSubjectSnapshot failed: %v", err)
	}

	if snapshot.Subject != "worker-01" {
		t.Errorf("expected subject worker-01, got %s", snapshot.Subject)
	}
	if snapshot.CurrentEpoch != 2 {
		t.Errorf("expected epoch 2, got %d", snapshot.CurrentEpoch)
	}
	if len(snapshot.ActiveGrants) != 2 {
		t.Fatalf("expected 2 active grants, got %d", len(snapshot.ActiveGrants))
	}
	expectedIDs := map[string]bool{"grant-1": true, "grant-3": true}
	for _, g := range snapshot.ActiveGrants {
		if !expectedIDs[g.ID] {
			t.Errorf("unexpected active grant id: %s", g.ID)
		}
	}
	if len(snapshot.RevokedGrants) != 1 {
		t.Fatalf("expected 1 revoked grant, got %d", len(snapshot.RevokedGrants))
	}
	if snapshot.RevokedGrants[0].ID != "grant-2" {
		t.Errorf("expected revoked grant id grant-2, got %s", snapshot.RevokedGrants[0].ID)
	}

	// 2. 미등록 주체 스냅샷 검증: Epoch는 기본값 1, ActiveGrants는 빈 슬라이스
	unregisteredSnapshot, err := svc.GetSubjectSnapshot(ctx, "worker-unregistered")
	if err != nil {
		t.Fatalf("GetSubjectSnapshot failed: %v", err)
	}
	if unregisteredSnapshot.CurrentEpoch != 1 {
		t.Errorf("expected default epoch 1, got %d", unregisteredSnapshot.CurrentEpoch)
	}
	if len(unregisteredSnapshot.ActiveGrants) != 0 {
		t.Errorf("expected 0 grants for unregistered subject, got %d", len(unregisteredSnapshot.ActiveGrants))
	}

	// 3. 빈 Subject 요청 시 에러
	_, err = svc.GetSubjectSnapshot(ctx, "")
	if err == nil {
		t.Errorf("expected error on empty subject, got nil")
	}
}

func TestPIP_GetActiveGrants(t *testing.T) {
	ctx := context.Background()
	svc, store := setupTestPIP(t)

	now := time.Now().UTC()
	_ = store.Update(func(st *state.GrantsState) error {
		st.Grants = append(st.Grants, domain.Grant{
			ID:        "grant-1",
			Subject:   "worker-01",
			Action:    domain.ActionFileRead,
			Resource:  "docs/a.txt",
			Status:    domain.GrantStatusActive,
			CreatedAt: now,
		})
		return nil
	})

	grants, err := svc.GetActiveGrants(ctx, "worker-01")
	if err != nil {
		t.Fatalf("GetActiveGrants failed: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != "grant-1" {
		t.Errorf("expected 1 grant with id grant-1, got %v", grants)
	}
}

func TestPIP_GetCurrentEpoch(t *testing.T) {
	ctx := context.Background()
	svc, store := setupTestPIP(t)

	_ = store.Update(func(st *state.GrantsState) error {
		st.Epochs["worker-01"] = 5
		return nil
	})

	epoch, err := svc.GetCurrentEpoch(ctx, "worker-01")
	if err != nil {
		t.Fatalf("GetCurrentEpoch failed: %v", err)
	}
	if epoch != 5 {
		t.Errorf("expected epoch 5, got %d", epoch)
	}

	// 미등록 주체
	defaultEpoch, err := svc.GetCurrentEpoch(ctx, "worker-new")
	if err != nil {
		t.Fatalf("GetCurrentEpoch failed: %v", err)
	}
	if defaultEpoch != 1 {
		t.Errorf("expected default epoch 1, got %d", defaultEpoch)
	}
}
