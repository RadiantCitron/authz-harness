package netguard_test

import (
	"strings"
	"testing"

	"authz-harness/internal/netguard"
)

// TC-020-08
func FuzzNetTarget(f *testing.F) {
	for _, s := range []string{
		"http://127.0.0.1:18080/status?x=1#f", "127.0.0.1:18080", "http://[::1]:18080/",
		"http://evil@127.0.0.1:80/", "http://2130706433:80/", "", "http://127.0.0.1:80?q",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		tg, err := netguard.ParseTarget(raw)
		if err != nil {
			return
		}
		if !strings.HasPrefix(tg.HostPort, "127.0.0.1:") && !strings.HasPrefix(tg.HostPort, "[::1]:") {
			t.Fatalf("bad HostPort %q from %q", tg.HostPort, raw)
		}
		again, err := netguard.ParseTarget(tg.URL)
		if err != nil || again != tg {
			t.Fatalf("not idempotent: %q -> %+v -> %+v, %v", raw, tg, again, err)
		}
	})
}
