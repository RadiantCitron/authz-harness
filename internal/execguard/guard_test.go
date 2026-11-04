package execguard

import (
	"context"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/domain"
)

func wantReason(t *testing.T, err error, r domain.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", r)
	}
	if got := domain.ReasonFromError(err, ""); got != r {
		t.Fatalf("expected %s, got %s (%v)", r, got, err)
	}
	if code := domain.ExitCodeFromError(err, 0); code != domain.ExitAuthzDenied {
		t.Fatalf("expected exit 12, got %d", code)
	}
}

// TC-030-01
func TestRun_Echo(t *testing.T) {
	r := NewRunner(t.TempDir(), 0, 0)
	for arg, want := range map[string]string{"hello_123": "hello_123\n", "": "\n"} {
		got, err := r.Run(context.Background(), "echo-safe", arg)
		if err != nil || string(got) != want {
			t.Errorf("Run(%q) = %q, %v; want %q", arg, got, err, want)
		}
	}
}

// TC-030-02
func TestValidate_IDDenied(t *testing.T) {
	for _, id := range []string{"sh", "/bin/echo", "../bin/echo", "echo-safe ", "ECHO-SAFE", "", "echo-safe\x00"} {
		wantReason(t, Validate(id, ""), domain.ReasonExecNotAllowed)
	}
}

// TC-030-03
func TestValidate_ArgRejected(t *testing.T) {
	for _, a := range []string{"-n", "--help", "a;b", "$(id)", "`id`", "a b", "a\nb", strings.Repeat("a", 65), "a|b", "a&b", "a/b", "a\x00b"} {
		wantReason(t, Validate("echo-safe", a), domain.ReasonExecArgRejected)
	}
	for _, a := range []string{"", "a", ".hidden", "a-b_c.d", strings.Repeat("a", 64)} {
		if err := Validate("echo-safe", a); err != nil {
			t.Errorf("Validate(%q) unexpected: %v", a, err)
		}
	}
}

// TC-030-04
func TestRun_OutputLimit(t *testing.T) {
	r := NewRunner(t.TempDir(), 4, 0)
	out, err := r.Run(context.Background(), "echo-safe", "hello_123")
	wantReason(t, err, domain.ReasonToolLimitExceeded)
	if out != nil {
		t.Fatal("output must not be returned")
	}
}

// TC-030-05
func TestRun_Timeout(t *testing.T) {
	r := NewRunner(t.TempDir(), 0, time.Nanosecond)
	out, err := r.Run(context.Background(), "echo-safe", "x")
	wantReason(t, err, domain.ReasonToolLimitExceeded)
	if out != nil {
		t.Fatal("output must not be returned")
	}
}

// Run 도 Validate 를 다시 부른다.
func TestRun_Revalidates(t *testing.T) {
	r := NewRunner(t.TempDir(), 0, 0)
	_, err := r.Run(context.Background(), "echo-safe", "-n")
	wantReason(t, err, domain.ReasonExecArgRejected)
}

// TC-030-06
func TestBuildCmd(t *testing.T) {
	dir := t.TempDir()
	cmd := NewRunner(dir, 0, 0).buildCmd(context.Background(), "echo-safe", "x")
	if cmd.Env == nil || len(cmd.Env) != 0 {
		t.Errorf("Env must be non-nil and empty, got %#v", cmd.Env)
	}
	if cmd.Dir != dir {
		t.Errorf("Dir = %q; want %q", cmd.Dir, dir)
	}
	if cmd.Path != "/bin/echo" {
		t.Errorf("Path = %q", cmd.Path)
	}
	if len(cmd.Args) != 2 || cmd.Args[1] != "x" {
		t.Errorf("Args = %#v", cmd.Args)
	}
}
