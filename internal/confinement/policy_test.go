package confinement_test

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
)

func TestPolicyValidate(t *testing.T) { // TC-010-01, TC-010-02
	tests := []struct {
		name    string
		p       confinement.Policy
		wantErr bool
	}{
		{"relative root", confinement.Policy{ProtectedRoot: "sandbox"}, true},
		{"empty root", confinement.Policy{}, true},
		{"relative write path", confinement.Policy{ProtectedRoot: "/r", WritePaths: []string{"../zone_a"}}, true},
		{"read path outside root", confinement.Policy{ProtectedRoot: "/r/sb", ReadPaths: []string{"/r/other"}}, true},
		{"read path sibling prefix", confinement.Policy{ProtectedRoot: "/r/sb", ReadPaths: []string{"/r/sbx"}}, true},
		{"read path via dotdot", confinement.Policy{ProtectedRoot: "/r/sb", ReadPaths: []string{"/r/sb/../zone_a"}}, true},
		{"valid", confinement.Policy{ProtectedRoot: "/r/sb", ReadPaths: []string{"/r/sb/ro"}, WritePaths: []string{"/r/sb/w"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var de *domain.Error
			if !errors.As(err, &de) || de.Reason != domain.ReasonInvalidArguments || de.ExitCode != domain.ExitBadInput {
				t.Fatalf("want INVALID_ARGUMENTS/14, got %v", err)
			}
		})
	}
}

func TestNoopConfiner(t *testing.T) { // TC-010-03, TC-010-04
	c := confinement.NoopConfiner{}
	if c.Name() != "none" || c.Available() {
		t.Fatalf("noop must be unavailable and named none")
	}
	p := confinement.Policy{ProtectedRoot: "/r"}

	cmd := exec.Command("/bin/true", "a")
	p.Require = true
	err := c.Prepare(cmd, p)
	var de *domain.Error
	if !errors.As(err, &de) || de.Reason != domain.ReasonConfinementUnavailable || de.ExitCode != domain.ExitInternalError {
		t.Fatalf("want CONFINEMENT_UNAVAILABLE/16, got %v", err)
	}

	cmd = exec.Command("/bin/true", "a")
	path, args := cmd.Path, append([]string(nil), cmd.Args...)
	p.Require = false
	if err := c.Prepare(cmd, p); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cmd.Path != path || strings.Join(cmd.Args, " ") != strings.Join(args, " ") {
		t.Fatalf("cmd must be unchanged")
	}
}

func TestWorkerPolicy(t *testing.T) { // TC-010-05
	root := "/r/sb"
	p := confinement.WorkerPolicy(root, root+"/workspace", root+"/zone_b", root+"/audit.jsonl")
	if len(p.WritePaths) != 4 || p.AllowNetwork || !p.Require || p.ReadPaths != nil {
		t.Fatalf("unexpected policy: %+v", p)
	}
	for _, w := range p.WritePaths {
		if strings.HasPrefix(w, root+"/zone_a") {
			t.Fatalf("zone_a must not be listed: %s", w)
		}
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("worker policy must validate: %v", err)
	}
}
