package catalog

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/subagent"
)

// 계획 020 인수 시험 B1·B2: inproc 브리지의 응답은 프로덕션 워커(subagent.SubagentWorker)의 응답과 같아야 한다.
// 기대값은 "subprocess 모드와 동형"이라는 요구사항에서 도출했다. 구현을 보고 역산하지 않는다.
func TestInProcBridge_ResponseMatchesProductionWorker(t *testing.T) {
	cases := []struct {
		name       string
		offsetSec  int64
		wantExit   domain.ExitCode
		wantReason string
	}{
		{"B2 정상 읽기: Output 이 파일 내용", 0, domain.ExitSuccess, string(domain.ReasonAuthorized)},
		{"B1 만료 토큰: 실제 거부 사유", 301, domain.ExitTokenInvalid, string(domain.ReasonTokenExpired)},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := harness.NewSandboxEnvironment(harness.SandboxConfig{BaseDir: t.TempDir()})
			if err != nil {
				t.Fatalf("sandbox: %v", err)
			}
			defer env.Cleanup()
			stack, err := setupHarnessStack(env)
			if err != nil {
				t.Fatalf("stack: %v", err)
			}
			defer stack.Close()

			if err := os.WriteFile(filepath.Join(env.WorkspaceDir, "task.txt"), []byte("payload"), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			sub := "bridge-fidelity"
			if _, err := stack.PAP.CreateGrant(context.Background(), pap.CreateGrantRequest{
				Subject: sub, Action: domain.ActionFileRead, Resource: "task.txt",
			}); err != nil {
				t.Fatalf("grant: %v", err)
			}
			tok, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01",
				sub, "file:read:task.txt", 5*time.Minute, token.IssueOptions{})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			// 토큰은 일회용(재사용 거부)이라 워커 비교용을 따로 발급한다. 같은 모의 시계라 만료 시각도 같다.
			tokForWorker, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01",
				sub, "file:read:task.txt", 5*time.Minute, token.IssueOptions{})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			req := subagent.SubagentRequest{
				TraceID: "tr-fid-" + string(rune('a'+i)), Token: tok, Action: "file:read",
				FilePath: "task.txt", ClockOffsetSeconds: tc.offsetSec,
			}

			got, err := (&inProcSpawnerBridge{stack: stack}).Spawn(context.Background(), req)
			if err != nil {
				t.Fatalf("spawn: %v", err)
			}
			if domain.ExitCode(got.ExitCode) != tc.wantExit {
				t.Fatalf("exit = %d, want %d", got.ExitCode, tc.wantExit)
			}
			if got.Response == nil {
				t.Fatal("bridge returned no response")
			}
			if got.Response.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Response.Reason, tc.wantReason)
			}
			if tc.wantExit == domain.ExitSuccess && got.Response.Output != "payload" {
				t.Errorf("output = %q, want payload", got.Response.Output)
			}

			// 같은 요청을 프로덕션 워커에 직접 주었을 때의 응답과 비교한다(필드 구성 동형성).
			worker, err := subagent.NewWorker(stack.PEP)
			if err != nil {
				t.Fatalf("worker: %v", err)
			}
			wantReq := req
			wantReq.Token = tokForWorker
			want, _ := worker.Execute(context.Background(), wantReq)
			if !reflect.DeepEqual(*got.Response, want) {
				t.Errorf("bridge response differs from production worker\n got: %+v\nwant: %+v", *got.Response, want)
			}
		})
	}
}
