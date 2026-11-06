package cli

import (
	"context"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

// 계획 020 O1·O2: orchestrate spawn 은 정식 액션 4종을 모두 액션 검증에서 통과시키고, 오타만 14 로 거부한다.
func TestOrchestrateSpawn_ActionValidation(t *testing.T) {
	for _, tc := range []struct {
		action       string
		wantRejected bool
	}{
		{"net:fetch", false}, {"exec:run", false}, {" READ ", false}, {"write", false},
		{"typo", true}, {"file:delete", true},
	} {
		t.Run(tc.action, func(t *testing.T) {
			rig := setupPEPCLITestRig(t)
			runner, err := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
			if err != nil {
				t.Fatal(err)
			}
			runner.SetWorkerBinaryPath(getTestBinary(t))
			code := runner.Run(context.Background(), []string{"spawn", "-token", "not.a.jwt", "-action", tc.action, "-file", "x.txt"})
			rejectedAtInput := code == domain.ExitBadInput && strings.Contains(rig.errOut.String(), "invalid")
			if rejectedAtInput != tc.wantRejected {
				t.Errorf("action %q: exit=%d rejectedAtInput=%v want %v (stderr: %s)",
					tc.action, code, rejectedAtInput, tc.wantRejected, rig.errOut.String())
			}
		})
	}
}
