package domain_test

import (
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

// 로드맵 19 / 010 TC-010-01: ADR 0007 2장 5번 표를 직접 적은 기대값
func TestPEPStagesMatchADR0007(t *testing.T) {
	want := []struct {
		id   domain.Stage
		kind domain.StageKind
		cond bool
	}{
		{"input", "check", false},
		{"authn", "check", false},
		{"authz", "decide", false},
		{"boundary", "check", false},
		{"replay", "consume", false},
		{"approval", "consume", true},
		{"budget", "consume", true},
		{"precommit_audit", "record", false},
		{"execute", "execute", false},
		{"settle", "settle", true},
	}
	got := domain.PEPStages()
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].ID != w.id || got[i].Kind != w.kind || got[i].Conditional != w.cond {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

// TC-010-02
func TestPEPStagesReturnsCopy(t *testing.T) {
	a := domain.PEPStages()
	a[0].ID = "tampered"
	a[0].Label = "tampered"
	if b := domain.PEPStages(); b[0].ID != domain.StageInput || b[0].Label == "tampered" {
		t.Errorf("internal list mutated: %+v", b[0])
	}
}

// TC-010-03
func TestPEPStagesIDLabelHygiene(t *testing.T) {
	ids, labels := map[domain.Stage]bool{}, map[string]bool{}
	for _, s := range domain.PEPStages() {
		if s.ID == "" || s.Label == "" {
			t.Errorf("empty ID/Label: %+v", s)
		}
		if ids[s.ID] || labels[s.Label] {
			t.Errorf("duplicate: %+v", s)
		}
		ids[s.ID], labels[s.Label] = true, true
		if strings.ContainsAny(string(s.ID)+s.Label, "0123456789") {
			t.Errorf("contains digit: %+v", s)
		}
	}
}
