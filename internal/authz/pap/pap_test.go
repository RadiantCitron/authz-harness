package pap_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

func setupTestPAP(t *testing.T) (pap.Service, string, string) {
	t.Helper()
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "grants_state.json")
	auditPath := filepath.Join(tempDir, "audit.jsonl")

	store, err := state.NewFileStore(statePath)
	if err != nil {
		t.Fatalf("failed to create FileStore: %v", err)
	}

	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("failed to create JSONLWriter: %v", err)
	}
	t.Cleanup(func() {
		_ = auditWriter.Close()
	})

	svc := pap.NewService(store, auditWriter)
	return svc, statePath, auditPath
}

func TestPAP_CreateGrant(t *testing.T) {
	ctx := context.Background()
	svc, _, auditPath := setupTestPAP(t)

	// 1. 유효한 Grant 생성
	req := pap.CreateGrantRequest{
		Subject:  "worker-01",
		Action:   domain.ActionFileRead,
		Resource: "docs/plan.txt",
	}

	grant, err := svc.CreateGrant(ctx, req)
	if err != nil {
		t.Fatalf("CreateGrant failed: %v", err)
	}

	if grant.ID == "" {
		t.Errorf("expected non-empty grant ID")
	}
	if grant.Subject != "worker-01" {
		t.Errorf("expected subject worker-01, got %s", grant.Subject)
	}
	if !grant.IsActive() {
		t.Errorf("expected grant to be active")
	}

	// 감사 로그 파일이 비어있지 않은지 검증
	info, err := os.Stat(auditPath)
	if err != nil || info.Size() == 0 {
		t.Errorf("expected audit.jsonl to contain event, got err=%v, size=%v", err, info.Size())
	}

	// 2. 경로 탈출(..) 시도 차단 검증
	invalidReq := pap.CreateGrantRequest{
		Subject:  "worker-01",
		Action:   domain.ActionFileRead,
		Resource: "../secret/plan.txt",
	}
	_, err = svc.CreateGrant(ctx, invalidReq)
	if err == nil {
		t.Errorf("expected error on path traversal, got nil")
	}
}

func TestPAP_RevokeGrant(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestPAP(t)

	// Grant 생성
	req := pap.CreateGrantRequest{
		Subject:  "worker-01",
		Action:   domain.ActionFileWrite,
		Resource: "output/report.txt",
	}
	grant, err := svc.CreateGrant(ctx, req)
	if err != nil {
		t.Fatalf("CreateGrant failed: %v", err)
	}

	// 정상 회수
	revoked, err := svc.RevokeGrant(ctx, grant.ID)
	if err != nil {
		t.Fatalf("RevokeGrant failed: %v", err)
	}
	if revoked.IsActive() {
		t.Errorf("expected revoked grant to be inactive")
	}
	if revoked.Status != domain.GrantStatusRevoked {
		t.Errorf("expected status revoked, got %s", revoked.Status)
	}
	if revoked.RevokedAt == nil {
		t.Errorf("expected RevokedAt to be set")
	}

	// 존재하지 않는 ID 회수 시도
	_, err = svc.RevokeGrant(ctx, "non-existent-id")
	if err == nil {
		t.Errorf("expected error when revoking non-existent grant, got nil")
	}
}

func TestPAP_BumpEpoch(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestPAP(t)

	// 초기 Epoch는 1이므로 Bump 시 2가 되어야 함
	epoch1, err := svc.BumpEpoch(ctx, "worker-01")
	if err != nil {
		t.Fatalf("BumpEpoch failed: %v", err)
	}
	if epoch1 != 2 {
		t.Errorf("expected epoch 2, got %d", epoch1)
	}

	epoch2, err := svc.BumpEpoch(ctx, "worker-01")
	if err != nil {
		t.Fatalf("BumpEpoch failed: %v", err)
	}
	if epoch2 != 3 {
		t.Errorf("expected epoch 3, got %d", epoch2)
	}

	// 빈 subject 에러
	_, err = svc.BumpEpoch(ctx, "")
	if err == nil {
		t.Errorf("expected error on empty subject, got nil")
	}
}

func TestPAP_ListGrants(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestPAP(t)

	// 2개의 Grant 생성
	g1, _ := svc.CreateGrant(ctx, pap.CreateGrantRequest{
		Subject:  "worker-01",
		Action:   domain.ActionFileRead,
		Resource: "docs/1.txt",
	})
	g2, _ := svc.CreateGrant(ctx, pap.CreateGrantRequest{
		Subject:  "worker-02",
		Action:   domain.ActionFileRead,
		Resource: "docs/2.txt",
	})

	// g1 회수
	_, _ = svc.RevokeGrant(ctx, g1.ID)

	// 전체 조회
	all, err := svc.ListGrants(ctx, pap.GrantFilter{})
	if err != nil {
		t.Fatalf("ListGrants failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 grants, got %d", len(all))
	}

	// Subject 필터
	w01Grants, err := svc.ListGrants(ctx, pap.GrantFilter{Subject: "worker-01"})
	if err != nil {
		t.Fatalf("ListGrants failed: %v", err)
	}
	if len(w01Grants) != 1 || w01Grants[0].ID != g1.ID {
		t.Errorf("expected 1 grant for worker-01, got %v", w01Grants)
	}

	// Status 필터: Active
	activeStatus := domain.GrantStatusActive
	activeGrants, err := svc.ListGrants(ctx, pap.GrantFilter{Status: &activeStatus})
	if err != nil {
		t.Fatalf("ListGrants failed: %v", err)
	}
	if len(activeGrants) != 1 || activeGrants[0].ID != g2.ID {
		t.Errorf("expected 1 active grant (g2), got %v", activeGrants)
	}
}

func TestPAP_Concurrency(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestPAP(t)

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			_, err := svc.CreateGrant(ctx, pap.CreateGrantRequest{
				Subject:  "worker-concurrent",
				Action:   domain.ActionFileRead,
				Resource: filepath.Join("docs", "test.txt"),
			})
			if err != nil {
				t.Errorf("concurrent CreateGrant failed: %v", err)
			}
		}(i)
	}

	wg.Wait()

	grants, err := svc.ListGrants(ctx, pap.GrantFilter{Subject: "worker-concurrent"})
	if err != nil {
		t.Fatalf("ListGrants failed: %v", err)
	}
	if len(grants) != concurrency {
		t.Errorf("expected %d grants, got %d", concurrency, len(grants))
	}
}
