package audit_test

import (
	"testing"

	"authz-harness/internal/audit"
)

// 계획 021 S1 — H4: 최상위 값 우선, 없으면 Metadata, 둘 다 없으면 빈 값.
func TestEffectiveHashes_H4(t *testing.T) {
	cases := []struct {
		name       string
		ev         audit.Event
		prev, curr string
	}{
		{"top-level wins", audit.Event{PrevHash: "p", CurrHash: "c", Metadata: map[string]interface{}{"prev_hash": "mp", "curr_hash": "mc"}}, "p", "c"},
		{"metadata fallback", audit.Event{Metadata: map[string]interface{}{"prev_hash": "mp", "curr_hash": "mc"}}, "mp", "mc"},
		{"neither", audit.Event{}, "", ""},
		{"non-string metadata ignored", audit.Event{Metadata: map[string]interface{}{"prev_hash": 1, "curr_hash": 2}}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.ev.EffectivePrevHash(); got != c.prev {
				t.Errorf("prev: got %q want %q", got, c.prev)
			}
			if got := c.ev.EffectiveCurrHash(); got != c.curr {
				t.Errorf("curr: got %q want %q", got, c.curr)
			}
		})
	}
}
