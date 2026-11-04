package state

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/domain"
)

func newApprovalStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(filepath.Join(t.TempDir(), "grants_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sampleApproval(id string, now time.Time, ttl time.Duration) domain.Approval {
	return domain.Approval{ID: id, Subject: "worker-01", Action: domain.ActionFileWrite, Resource: "secret.txt",
		TokenJTI: "jti-01", CreatedAt: now, ExpiresAt: now.Add(ttl)}
}

func bindingOf(a domain.Approval) domain.ApprovalBinding {
	return domain.ApprovalBinding{Subject: a.Subject, Action: a.Action, Resource: a.Resource, TokenJTI: a.TokenJTI, ArgHash: a.ArgHash}
}

func TestApprovalConsumeConcurrent(t *testing.T) { // TC-020-01
	s := newApprovalStore(t)
	now := time.Now()
	a := sampleApproval("ap-1", now, time.Minute)
	if err := CreateApproval(s, a, now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = ConsumeApproval(s, "ap-1", bindingOf(a), now)
		}()
	}
	wg.Wait()
	ok := 0
	for _, e := range errs {
		if e == nil {
			ok++
		} else if domain.ReasonFromError(e, "") != domain.ReasonApprovalRequired || domain.ExitCodeFromError(e, 0) != domain.ExitApprovalRequired {
			t.Errorf("unexpected error: %v", e)
		}
	}
	if ok != 1 {
		t.Fatalf("expected exactly 1 success, got %d", ok)
	}
	st, _ := s.Load()
	if len(st.Approvals) != 0 {
		t.Fatalf("approvals left: %d", len(st.Approvals))
	}
}

func TestApprovalConsumeMismatchAndExpired(t *testing.T) { // TC-020-02
	s := newApprovalStore(t)
	now := time.Now()
	a := sampleApproval("ap-1", now, time.Minute)
	a.ArgHash = domain.DataDigest([]byte("a"))
	if err := CreateApproval(s, a, now); err != nil {
		t.Fatal(err)
	}
	b := bindingOf(a)
	b.ArgHash = domain.DataDigest([]byte("tampered"))
	if r := domain.ReasonFromError(ConsumeApproval(s, "ap-1", b, now), ""); r != domain.ReasonApprovalMismatch {
		t.Fatalf("mismatch: %s", r)
	}
	if st, _ := s.Load(); len(st.Approvals) != 1 {
		t.Fatalf("mismatch must not delete: %d", len(st.Approvals))
	}
	// 만료 시각 이후: 정리되어 REQUIRED (같은 18)
	err := ConsumeApproval(s, "ap-1", bindingOf(a), a.ExpiresAt)
	if domain.ExitCodeFromError(err, 0) != domain.ExitApprovalRequired {
		t.Fatalf("expired: %v", err)
	}
	if st, _ := s.Load(); len(st.Approvals) != 0 {
		t.Fatalf("expired approval must be pruned: %d", len(st.Approvals))
	}
}

func TestApprovalCreatePrunesExpired(t *testing.T) { // TC-020-03
	s := newApprovalStore(t)
	now := time.Now()
	if err := CreateApproval(s, sampleApproval("old", now.Add(-time.Hour), time.Minute), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := CreateApproval(s, sampleApproval("live", now, time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := CreateApproval(s, sampleApproval("new", now, time.Minute), now); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Load()
	if len(st.Approvals) != 2 || st.Approvals[0].ID != "live" || st.Approvals[1].ID != "new" {
		t.Fatalf("got %+v", st.Approvals)
	}
	if err := CreateApproval(s, sampleApproval("new", now, time.Minute), now); domain.ExitCodeFromError(err, 0) != domain.ExitInternalError {
		t.Fatalf("duplicate id must fail with 16: %v", err)
	}
}

func TestApprovalLegacyStateFile(t *testing.T) { // TC-020-08
	p := filepath.Join(t.TempDir(), "grants_state.json")
	legacy := `{"version":1,"updated_at":"2026-01-01T00:00:00Z","grants":[],"epochs":{}}`
	if err := os.WriteFile(p, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil || st.Approvals == nil || len(st.Approvals) != 0 {
		t.Fatalf("legacy load: %v %+v", err, st)
	}
}
