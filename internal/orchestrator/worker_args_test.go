package orchestrator

import (
	"reflect"
	"testing"
)

// 계획 022 W1: 필수 플래그는 항상, -net-allow·-verbose 는 조건부로만 전달된다.
func TestWorkerArgs(t *testing.T) {
	base := []string{"subagent", "worker", "-workspace", "/w", "-state-file", "/s", "-pub-jwks-file", "/p", "-replay-file", "/r", "-audit-file", "/a"}
	cases := []struct {
		name    string
		net     string
		verbose bool
		want    []string
	}{
		{"기본", "", false, base},
		{"공백 net-allow 는 생략", "  ", false, base},
		{"net-allow", "127.0.0.1:1", false, append(append([]string{}, base...), "-net-allow", "127.0.0.1:1")},
		{"verbose", "", true, append(append([]string{}, base...), "-verbose")},
		{"둘 다", "h:1", true, append(append([]string{}, base...), "-net-allow", "h:1", "-verbose")},
	}
	for _, c := range cases {
		if got := WorkerArgs("/w", "/s", "/p", "/r", "/a", c.net, c.verbose); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
