package domain

import (
	"testing"
	"time"
)

func approvalFixture() (Approval, ApprovalBinding, time.Time) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	arg := DataDigest([]byte("payload"))
	a := Approval{ID: "ap-1", Subject: "agent-a", Action: ActionFileWrite, Resource: "out.txt",
		TokenJTI: "jti-1", ArgHash: arg, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	b := ApprovalBinding{Subject: "agent-a", Action: ActionFileWrite, Resource: "out.txt", TokenJTI: "jti-1", ArgHash: arg}
	return a, b, now
}

func TestApprovalMatches(t *testing.T) { // TC-010-01~03
	a, b, now := approvalFixture()
	if got := a.Matches(b, now); got != ReasonAuthorized {
		t.Fatalf("exact match: %s", got)
	}
	free := a
	free.ArgHash = ""
	b2 := b
	b2.ArgHash = DataDigest([]byte("anything"))
	if got := free.Matches(b2, now); got != ReasonAuthorized {
		t.Fatalf("no arg binding: %s", got)
	}
	mut := map[string]func(*ApprovalBinding){
		"subject":  func(x *ApprovalBinding) { x.Subject = "other" },
		"action":   func(x *ApprovalBinding) { x.Action = ActionFileRead },
		"resource": func(x *ApprovalBinding) { x.Resource = "other.txt" },
		"jti":      func(x *ApprovalBinding) { x.TokenJTI = "jti-2" },
		"arghash":  func(x *ApprovalBinding) { x.ArgHash = DataDigest([]byte("tampered")) },
	}
	for name, f := range mut {
		bb := b
		f(&bb)
		got := a.Matches(bb, now)
		if got != ReasonApprovalMismatch || ExitCodeForReason(got) != ExitApprovalRequired {
			t.Errorf("%s: got %s", name, got)
		}
	}
	if got := a.Matches(b, a.ExpiresAt); got != ReasonApprovalExpired {
		t.Fatalf("now == ExpiresAt: %s", got)
	}
}

func TestSelectApproval(t *testing.T) { // TC-010-03
	a, b, now := approvalFixture()
	expired := a
	expired.ID = "ap-exp"
	expired.ExpiresAt = now.Add(-time.Second)
	mismatch := a
	mismatch.ID = "ap-mm"
	mismatch.Resource = "other.txt"
	foreign := a
	foreign.ID = "ap-foreign"
	foreign.Subject = "someone"

	tests := []struct {
		name   string
		list   []Approval
		wantID string
		want   Reason
	}{
		{"expired+mismatch", []Approval{expired, mismatch}, "", ReasonApprovalExpired},
		{"mismatch only", []Approval{mismatch}, "", ReasonApprovalMismatch},
		{"other subject only", []Approval{foreign}, "", ReasonApprovalRequired},
		{"empty", nil, "", ReasonApprovalRequired},
		{"valid+expired", []Approval{expired, a}, "ap-1", ReasonAuthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, r := SelectApproval(tc.list, b, now)
			if id != tc.wantID || r != tc.want {
				t.Fatalf("got (%q,%s) want (%q,%s)", id, r, tc.wantID, tc.want)
			}
		})
	}
}

func TestApprovalValidators(t *testing.T) { // TC-010-04
	ttls := []struct {
		in      time.Duration
		want    time.Duration
		wantErr bool
	}{
		{0, DefaultApprovalTTL, false},
		{-time.Second, 0, true},
		{2 * time.Hour, 0, true},
		{time.Hour, time.Hour, false},
	}
	for _, tc := range ttls {
		got, err := ValidateApprovalTTL(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ttl %s: got (%s,%v)", tc.in, got, err)
		}
		if err != nil && ExitCodeFromError(err, 0) != ExitBadInput {
			t.Errorf("ttl %s: exit %d", tc.in, ExitCodeFromError(err, 0))
		}
	}
	hashes := []struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{DataDigest([]byte("x")), false},
		{"sha256:XYZ", true},
		{"md5:d41d8cd98f00b204e9800998ecf8427e", true},
	}
	for _, tc := range hashes {
		err := ValidateArgHash(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("arg_hash %q: err=%v", tc.in, err)
		}
		if err != nil && ExitCodeFromError(err, 0) != ExitBadInput {
			t.Errorf("arg_hash %q: exit %d", tc.in, ExitCodeFromError(err, 0))
		}
	}
}
