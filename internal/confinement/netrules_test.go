package confinement

import "testing"

// 로드맵 16 / 055 TC-055-05 (규칙 생성부, 플랫폼 중립)
func TestLandlockNetRules(t *testing.T) {
	rules := landlockNetRules(Policy{AllowConnectPorts: []int{8080, 9090, 8080}})
	if len(rules) != 2 || rules[0].port != 8080 || rules[1].port != 9090 {
		t.Fatalf("rules = %+v", rules)
	}
	for _, r := range rules {
		if r.access != connectTCPAccess {
			t.Errorf("access = %d", r.access)
		}
	}
	if got := landlockNetRules(Policy{}); len(got) != 0 {
		t.Errorf("no ports must give no rules, got %v", got)
	}
	if got := landlockNetRules(Policy{AllowNetwork: true, AllowConnectPorts: []int{1}}); len(got) != 0 {
		t.Errorf("AllowNetwork must give no rules, got %v", got)
	}
}
