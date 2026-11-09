package cli

import (
	"context"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

// 계획 020 O1·O2 및 계획 032 D-02: orchestrate spawn 은 정식 액션 4종을 모두 액션 검증에서 통과시키고,
// 위조 토큰에 대해 토큰 검증 실패(ExitTokenInvalid=11)를 반환한다. 오타/미허용 액션만 인자 오류(ExitBadInput=14)로 거부한다.
func TestOrchestrateSpawn_ActionValidation(t *testing.T) {
	for _, tc := range []struct {
		action   string
		target   string
		wantCode domain.ExitCode
	}{
		{"net:fetch", "http://127.0.0.1:18080/data", domain.ExitTokenInvalid},
		{"exec:run", "x.txt", domain.ExitTokenInvalid},
		{" READ ", "x.txt", domain.ExitTokenInvalid},
		{"write", "x.txt", domain.ExitTokenInvalid},
		{"typo", "x.txt", domain.ExitBadInput},
		{"file:delete", "x.txt", domain.ExitBadInput},
	} {
		t.Run(tc.action, func(t *testing.T) {
			rig := setupPEPCLITestRig(t)
			runner := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
			runner.SetWorkerBinaryPath(getTestBinary(t))
			code := runner.Run(context.Background(), []string{"spawn", "-token", "not.a.jwt", "-action", tc.action, "-file", tc.target})
			if code != tc.wantCode {
				t.Errorf("action %q: got exit=%d want %d (stderr: %s)",
					tc.action, code, tc.wantCode, rig.errOut.String())
			}
			if tc.wantCode == domain.ExitBadInput && !strings.Contains(rig.errOut.String(), "invalid") {
				t.Errorf("action %q: expected 'invalid' in stderr on ExitBadInput, got: %s", tc.action, rig.errOut.String())
			}
		})
	}
}
