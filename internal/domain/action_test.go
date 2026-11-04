package domain_test

import (
	"testing"

	"authz-harness/internal/domain"
)

// 로드맵 16 / 010 TC-010-01
func TestParseAction(t *testing.T) {
	ok := map[string]domain.Action{
		"net:fetch":  domain.ActionNetFetch,
		" EXEC:RUN ": domain.ActionExecRun,
		"read":       domain.ActionFileRead,
		"file:write": domain.ActionFileWrite,
	}
	for in, want := range ok {
		got, err := domain.ParseAction(in)
		if err != nil || got != want {
			t.Errorf("ParseAction(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"net:post", "exec", "", "net:fetch:127.0.0.1:1"} {
		if got, err := domain.ParseAction(in); err == nil {
			t.Errorf("ParseAction(%q) = %q, want error", in, got)
		}
	}
	if domain.IsValidAction("read") {
		t.Error(`IsValidAction("read") must be false`)
	}
}

// 로드맵 16 / 010 TC-010-02 (현행 ScopeMatches 회귀 고정)
func TestScopeMatches_NewTools(t *testing.T) {
	cases := []struct {
		scope, act, res string
		want            bool
	}{
		{"net:fetch:[::1]:18080", "net:fetch", "[::1]:18080", true},
		{"exec:run:echo-safe", "exec:run", "echo-safe", true},
		{"net:fetch:127.0.0.1:18080", "net:fetch", "127.0.0.1:9999", false},
	}
	for _, c := range cases {
		if got := domain.ScopeMatches(c.scope, domain.Action(c.act), c.res); got != c.want {
			t.Errorf("ScopeMatches(%q,%q,%q) = %v; want %v", c.scope, c.act, c.res, got, c.want)
		}
	}
}

// 로드맵 16 / 010 TC-010-04
func TestExitCodeForReason_NewToolReasons(t *testing.T) {
	for _, r := range []domain.Reason{
		domain.ReasonEgressDenied, domain.ReasonExecNotAllowed,
		domain.ReasonExecArgRejected, domain.ReasonToolLimitExceeded,
	} {
		if got := domain.ExitCodeForReason(r); got != domain.ExitAuthzDenied {
			t.Errorf("ExitCodeForReason(%s) = %d; want %d", r, got, domain.ExitAuthzDenied)
		}
	}
}
