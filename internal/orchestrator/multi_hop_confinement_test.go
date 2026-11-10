package orchestrator

import (
	"os"
	"testing"

	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
)

// 계획 048 인수 시험 M1·M2. 기대값은 요구사항에서 도출했다:
//   - M1: 격리 설정이 없으면(영값) 격리 사실이 감사에 나타나지 않는다 (기존 동작 불변).
//   - M2: 격리 필수인데 적용할 수 없으면 마지막 워커를 띄우지 않고 거부한다 (Fail-Closed).

// lightWorkerBinary 는 워커 인자를 무시하고 즉시 끝나는 실행 파일 경로를 돌려준다.
// 테스트 바이너리 자신을 워커로 쓰면 전체 시험이 재실행되므로 쓰지 않는다.
func lightWorkerBinary(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/usr/bin/true", "/bin/true"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("true 실행 파일을 찾을 수 없다")
	return ""
}

func confinedEvents(t *testing.T, auditPath string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	for _, ev := range auditEvents(t, auditPath) {
		if ev["action"] == AuditActionAgentConfined {
			out = append(out, ev)
		}
	}
	return out
}

func spawnEvents(t *testing.T, auditPath string) int {
	t.Helper()
	n := 0
	for _, ev := range auditEvents(t, auditPath) {
		if ev["step"] == "orchestrator.spawn" {
			n++
		}
	}
	return n
}

func TestMultiHop_ConfinementZeroValueLeavesNoConfinedEvent(t *testing.T) {
	env := newHopEnv(t)
	cfg := env.cfg
	cfg.BinaryPath = lightWorkerBinary(t) // 서브프로세스 경로. 인자를 무시하고 바로 끝나는 실행 파일이면 충분하다.
	cfg.Gateway = nil

	_, _ = env.run(t, cfg, env.stack.ExchangeService, "file:read file:write", "file:read")

	if n := len(confinedEvents(t, env.auditPath)); n != 0 {
		t.Fatalf("격리 설정이 없는데 agent.confined 가 %d건 기록되었다", n)
	}
	if spawnEvents(t, env.auditPath) == 0 {
		t.Fatal("대조군 실패: 워커 스폰 경로가 실행되지 않았다 (격리 이벤트가 없다는 관찰이 무의미해진다)")
	}
}

func TestMultiHop_RequireConfinementWithoutConfinerFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		confiner confinement.Confiner
	}{
		{"격리기 없음", nil},
		{"NoopConfiner", confinement.NoopConfiner{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newHopEnv(t)
			cfg := env.cfg
			cfg.BinaryPath = lightWorkerBinary(t)
			cfg.Gateway = nil
			cfg.Confiner = tc.confiner
			cfg.Confinement = confinement.Policy{Require: true}

			exit, _ := env.run(t, cfg, env.stack.ExchangeService, "file:read file:write", "file:read")

			if exit != domain.ExitInternalError {
				t.Fatalf("exit = %v, want %v (CONFINEMENT_UNAVAILABLE)", exit, domain.ExitInternalError)
			}
			evs := confinedEvents(t, env.auditPath)
			if len(evs) != 1 || evs[0]["decision"] != "deny" {
				t.Fatalf("agent.confined 는 deny 1건이어야 한다: %v", evs)
			}
		})
	}
}
