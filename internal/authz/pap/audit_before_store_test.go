package pap_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
)

// 계획 021 S1 — R2: 늘림 쪽(CreateGrant·CreateApproval)은 감사를 저장 앞에 기록한다 (인수 시험 O1~O6).

// peekWriter 는 Log 시점에 저장소를 읽어 항목 수를 기록하고, failOn 번째 Log(1-base)부터 실패시킨다.
type peekWriter struct {
	store          state.Store
	events         []audit.Event
	grantsAtLog    []int
	approvalsAtLog []int
	failFrom       int // 0 이면 실패 없음
	calls          int
}

func (p *peekWriter) Log(e audit.Event) error {
	p.calls++
	loaded, err := p.store.Load()
	if err != nil {
		return err
	}
	p.grantsAtLog = append(p.grantsAtLog, len(loaded.Grants))
	p.approvalsAtLog = append(p.approvalsAtLog, len(loaded.Approvals))
	if p.failFrom > 0 && p.calls >= p.failFrom {
		return errors.New("injected")
	}
	p.events = append(p.events, e)
	return nil
}
func (p *peekWriter) Close() error { return nil }

// countUpdateStore 는 Update 호출 수를 센다. failAll 이면 모든 Update 가 실패한다.
type countUpdateStore struct {
	state.Store
	updates int
	failAll bool
}

func (c *countUpdateStore) Update(fn func(*state.GrantsState) error) error {
	c.updates++
	if c.failAll {
		return errors.New("store injected")
	}
	return c.Store.Update(fn)
}

func newOrderStore(t *testing.T) *state.FileStore {
	return mustStore(t, filepath.Join(t.TempDir(), "s.json"))
}

// seedApprovalGrant 는 approvalReq 가 ADR 0011 D-4 허가 검사를 통과하도록 승인 필요 Grant 를 감사 없이 미리 넣는다.
func seedApprovalGrant(t *testing.T, st *state.FileStore) {
	t.Helper()
	seedGrant(t, st, approvalReq.Subject, approvalReq.Action, approvalReq.Resource, true, domain.GrantStatusActive)
}

var (
	grantReq    = pap.CreateGrantRequest{Subject: "w", Action: domain.ActionFileRead, Resource: "x"}
	approvalReq = pap.CreateApprovalRequest{Subject: "w", Action: domain.ActionFileWrite, Resource: "x", TokenJTI: "j"}
)

// O1: grant.created 를 기록하는 시점에 그 Grant 는 아직 저장소에 없다.
func TestOrder_O1_GrantAuditedBeforeStore(t *testing.T) {
	st := newOrderStore(t)
	w := &peekWriter{store: st}
	g, err := pap.NewService(st, w).CreateGrant(context.Background(), grantReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.grantsAtLog) != 1 || w.grantsAtLog[0] != 0 {
		t.Fatalf("grant must not be stored at audit time: %v", w.grantsAtLog)
	}
	loaded, _ := st.Load()
	if len(loaded.Grants) != 1 || loaded.Grants[0].ID != g.ID {
		t.Fatalf("grant must be stored afterwards: %+v", loaded.Grants)
	}
}

// O2: approval.granted 를 기록하는 시점에 그 승인은 아직 저장소에 없다.
func TestOrder_O2_ApprovalAuditedBeforeStore(t *testing.T) {
	st := newOrderStore(t)
	seedApprovalGrant(t, st)
	w := &peekWriter{store: st}
	if _, err := pap.NewService(st, w).CreateApproval(context.Background(), approvalReq); err != nil {
		t.Fatal(err)
	}
	if len(w.approvalsAtLog) != 1 || w.approvalsAtLog[0] != 0 {
		t.Fatalf("approval must not be stored at audit time: %v", w.approvalsAtLog)
	}
	loaded, _ := st.Load()
	if len(loaded.Approvals) != 1 {
		t.Fatalf("approval must be stored afterwards: %+v", loaded.Approvals)
	}
}

// O3: 감사 실패 → 15, 저장소 Update 0회, 항목 없음 (되돌리기 자체가 없다).
func TestOrder_O3_AuditFailureNeverTouchesStore(t *testing.T) {
	st := newOrderStore(t)
	cs := &countUpdateStore{Store: st}
	svc := pap.NewService(cs, failingWriter{})
	ctx := context.Background()
	if _, err := svc.CreateGrant(ctx, grantReq); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("grant: %v", err)
	}
	if _, err := svc.CreateApproval(ctx, approvalReq); domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("approval: %v", err)
	}
	if cs.updates != 0 {
		t.Fatalf("store Update must not be called, got %d", cs.updates)
	}
	loaded, _ := st.Load()
	if len(loaded.Grants) != 0 || len(loaded.Approvals) != 0 {
		t.Fatalf("entries must not exist: %+v", loaded)
	}
}

// O4: 저장 실패 → INTERNAL_ERROR, 감사에 *.created(granted) 뒤 같은 ID 의 *.deny.
func TestOrder_O4_StoreFailureLeavesCreatedThenDenySameID(t *testing.T) {
	cases := []struct {
		name, created, deny, idKey string
		call                       func(pap.Service) error
	}{
		{"grant", "grant.created", "grant.create.deny", "grant_id", func(s pap.Service) error {
			_, err := s.CreateGrant(context.Background(), grantReq)
			return err
		}},
		{"approval", "approval.granted", "approval.create.deny", "approval_id", func(s pap.Service) error {
			_, err := s.CreateApproval(context.Background(), approvalReq)
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := newOrderStore(t)
			if c.name == "approval" {
				seedApprovalGrant(t, st)
			}
			w := &peekWriter{store: st}
			err := c.call(pap.NewService(&countUpdateStore{Store: st, failAll: true}, w))
			if domain.ReasonFromError(err, "") != domain.ReasonInternalError {
				t.Fatalf("want INTERNAL_ERROR, got %v", err)
			}
			if len(w.events) != 2 || w.events[0].Action != c.created || w.events[1].Action != c.deny {
				t.Fatalf("want [%s %s], got %+v", c.created, c.deny, w.events)
			}
			id0, _ := w.events[0].Metadata[c.idKey].(string)
			id1, _ := w.events[1].Metadata[c.idKey].(string)
			if id0 == "" || id0 != id1 {
				t.Fatalf("deny must carry the same %s: %q vs %q", c.idKey, id0, id1)
			}
		})
	}
}

// O5: 저장 실패 뒤 거부 기록까지 실패 → AUDIT_LOG_FAILED.
func TestOrder_O5_DenyAuditAlsoFails(t *testing.T) {
	st := newOrderStore(t)
	w := &peekWriter{store: st, failFrom: 2}
	_, err := pap.NewService(&countUpdateStore{Store: st, failAll: true}, w).CreateGrant(context.Background(), grantReq)
	if domain.ReasonFromError(err, "") != domain.ReasonAuditLogFailed {
		t.Fatalf("want AUDIT_LOG_FAILED, got %v", err)
	}
}

// O6: 정상 생성 → 감사 1건, 항목 1건, 기록 내용 유지.
func TestOrder_O6_NormalCreateOneAuditOneEntry(t *testing.T) {
	st := newOrderStore(t)
	seedApprovalGrant(t, st)
	w := &peekWriter{store: st}
	svc := pap.NewService(st, w)
	g, err := svc.CreateGrant(context.Background(), grantReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.events) != 1 || w.events[0].Action != "grant.created" || w.events[0].Metadata["grant_id"] != g.ID || !w.events[0].Success {
		t.Fatalf("unexpected audit: %+v", w.events)
	}
	if _, err := svc.CreateApproval(context.Background(), approvalReq); err != nil {
		t.Fatal(err)
	}
	if len(w.events) != 2 || w.events[1].Action != "approval.granted" {
		t.Fatalf("unexpected audit: %+v", w.events)
	}
}
