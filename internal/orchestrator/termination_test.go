package orchestrator

import (
	"testing"

	"authz-harness/internal/domain"
)

func TestTC_020_03_ClassifyExit(t *testing.T) {
	tests := []struct {
		name       string
		term       Termination
		raw        int
		childRsn   string
		wantCode   domain.ExitCode
		wantReason domain.Reason
	}{
		{"output", TermOutputExceeded, -1, "", 17, domain.ReasonResourceOutputLimit},
		{"timeout", TermTimedOut, -1, "", 17, domain.ReasonResourceTimeout},
		{"canceled", TermCanceled, -1, "", 16, domain.ReasonSubprocessAbnormalExit},
		{"signaled", TermSignaled, -1, "", 16, domain.ReasonSubprocessAbnormalExit},
		{"exit0", TermExited, 0, "", 0, ""},
		{"exit12", TermExited, 12, "NO_ACTIVE_GRANT", 12, "NO_ACTIVE_GRANT"},
		{"exit11", TermExited, 11, "", 11, ""},
		{"exit16", TermExited, 16, "", 16, ""},
		{"exit1 abnormal", TermExited, 1, "", 16, domain.ReasonSubprocessAbnormalExit},
		{"exit2 abnormal", TermExited, 2, "", 16, domain.ReasonSubprocessAbnormalExit},
		{"exit17 from child is not trusted", TermExited, 17, "", 16, domain.ReasonSubprocessAbnormalExit},
		{"exit10 abnormal", TermExited, 10, "", 16, domain.ReasonSubprocessAbnormalExit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, reason := classifyExit(tc.term, tc.raw, tc.childRsn)
			if code != tc.wantCode || reason != tc.wantReason {
				t.Fatalf("got (%d, %q) want (%d, %q)", code, reason, tc.wantCode, tc.wantReason)
			}
		})
	}
}
