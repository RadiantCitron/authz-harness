package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBudget_Validate_Invalid(t *testing.T) { // TC-010-01
	tests := []struct {
		name string
		b    Budget
	}{
		{"MaxCalls 0", Budget{MaxCalls: 0}},
		{"MaxCalls -1", Budget{MaxCalls: -1}},
		{"MaxReadBytes -1", Budget{MaxCalls: 1, MaxReadBytes: -1}},
		{"MaxWriteBytes -1", Budget{MaxCalls: 1, MaxWriteBytes: -1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.b.Validate()
			var de *Error
			if !errors.As(err, &de) {
				t.Fatalf("want *domain.Error, got %v", err)
			}
			if de.Reason != ReasonInvalidArguments || de.ExitCode != ExitBadInput {
				t.Fatalf("got %s/%d", de.Reason, de.ExitCode)
			}
		})
	}
}

func TestBudget_Limits(t *testing.T) { // TC-010-02
	b := Budget{MaxCalls: 3, MaxReadBytes: 0, MaxWriteBytes: 100}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.HasReadLimit() || !b.HasWriteLimit() {
		t.Fatalf("read=%v write=%v", b.HasReadLimit(), b.HasWriteLimit())
	}
}

func TestBudget_ReasonExitCodes(t *testing.T) { // TC-010-03
	for _, r := range []Reason{ReasonBudgetExhausted, ReasonDelegationBudgetExceeded} {
		if got := ExitCodeForReason(r); got != ExitAuthzDenied {
			t.Errorf("%s: got %d want %d", r, got, ExitAuthzDenied)
		}
	}
}

func TestBudget_NilOmittedFromJSON(t *testing.T) { // TC-010-04
	b, err := json.Marshal(TokenClaims{Issuer: "i"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "budget") {
		t.Fatalf("budget key present: %s", b)
	}
	var back TokenClaims
	if err := json.Unmarshal(b, &back); err != nil || back.Budget != nil {
		t.Fatalf("roundtrip: %v %v", err, back.Budget)
	}
}

func TestBudget_Within(t *testing.T) { // TC-010-05
	upper := Budget{MaxCalls: 5, MaxWriteBytes: 20}
	tests := []struct {
		name  string
		b     Budget
		upper Budget
		want  bool
	}{
		{"이내", Budget{MaxCalls: 3, MaxWriteBytes: 10}, upper, true},
		{"횟수 초과", Budget{MaxCalls: 6, MaxWriteBytes: 10}, upper, false},
		{"쓰기 한도 격상", Budget{MaxCalls: 3}, upper, false},
		{"쓰기 바이트 초과", Budget{MaxCalls: 3, MaxWriteBytes: 21}, upper, false},
		{"상위 무한도면 하위 자유", Budget{MaxCalls: 2, MaxReadBytes: 9}, Budget{MaxCalls: 5}, true},
		{"읽기 한도 격상", Budget{MaxCalls: 1}, Budget{MaxCalls: 5, MaxReadBytes: 5}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.b.Within(tc.upper); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestBudget_ClaimsValidate(t *testing.T) { // TC-010-06
	now := time.Now().Unix()
	c := TokenClaims{Issuer: "i", Subject: "s", Audience: "a", ClientID: "c",
		ExpiresAt: now + 60, IssuedAt: now, JWTID: "j", Epoch: 1,
		Budget: &Budget{MaxCalls: 0}}
	if err := c.Validate(); err == nil {
		t.Fatal("invalid budget claim must be rejected")
	}
	c.Budget = &Budget{MaxCalls: 1}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid budget: %v", err)
	}
}
