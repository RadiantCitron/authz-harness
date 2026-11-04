package cli

import (
	"bytes"
	"runtime"
	"testing"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
)

func TestConfineExec(t *testing.T) {
	enc, err := confinement.EncodePolicy(confinement.WorkerPolicy("/r", "/r/w", "/r/b", "/r/a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
	}{
		{"broken policy", []string{"-policy", "!!!", "--", "/usr/bin/true"}},
		{"missing target", []string{"-policy", enc}},
		{"missing policy", []string{"--", "/usr/bin/true"}},
	}
	if runtime.GOOS != "linux" { // TC-030-04: 비-Linux 에서는 적용 불가이므로 대상 미실행 + 16
		cases = append(cases, struct {
			name string
			args []string
		}{"non-linux apply", []string{"-policy", enc, "--", "/usr/bin/true"}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errb bytes.Buffer
			if got := RunConfineExec(tc.args, &errb); got != domain.ExitInternalError {
				t.Fatalf("want 16, got %d", got)
			}
			if errb.Len() == 0 {
				t.Fatal("reason must be written to stderr")
			}
		})
	}
}
