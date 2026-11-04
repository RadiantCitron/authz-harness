package confinement_test

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"testing"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
)

func TestPolicyCodec(t *testing.T) { // TC-030-03
	p := confinement.WorkerPolicy("/r", "/r/w", "/r/b", "/r/a.jsonl")
	p.ReadPaths = []string{"/r/ro"}
	enc, err := confinement.EncodePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := confinement.DecodePolicy(enc)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("roundtrip mismatch: %v %+v", err, got)
	}
	for _, bad := range []string{"!!!", "bm90LWpzb24"} { // 비 base64, 비 JSON
		_, err := confinement.DecodePolicy(bad)
		var de *domain.Error
		if !errors.As(err, &de) || de.ExitCode != domain.ExitBadInput {
			t.Errorf("%q: want 14, got %v", bad, err)
		}
	}
}

func TestApplySelfNonLinux(t *testing.T) { // TC-030-02
	if runtime.GOOS == "linux" {
		t.Skip("linux: real landlock path")
	}
	err := confinement.ApplySelf(confinement.WorkerPolicy("/r", "/r/w", "/r/b", "/r/a.jsonl"))
	var de *domain.Error
	if !errors.As(err, &de) || de.Reason != domain.ReasonConfinementUnavailable || de.ExitCode != domain.ExitInternalError {
		t.Fatalf("want 16, got %v", err)
	}
}

func TestCrossCompileLinux(t *testing.T) { // TC-030-01
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found")
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(goBin, args...)
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, out)
		}
	}
	run("vet", "./internal/confinement/...", "./internal/cli/...")
	run("test", "-c", "-o", os.DevNull, "./internal/confinement")
}
