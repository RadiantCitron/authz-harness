package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/mcp"
)

type dummyMCPExecutor struct{}

func (d *dummyMCPExecutor) ExecuteTool(ctx context.Context, req *mcp.ToolCallRequest) (*mcp.ToolExecutionResult, error) {
	return &mcp.ToolExecutionResult{
		Content: []mcp.ToolContent{
			{Type: "text", Text: "dummy output"},
		},
	}, nil
}

func TestMCPRunner_ServePipe(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"
	in := strings.NewReader(input)
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	runner := NewMCPRunner(in, out, errOut, "", "", "", "", "", &dummyMCPExecutor{})
	code := runner.Run(context.Background(), []string{"serve"})

	if code != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess(0), got %v (stderr: %s)", code, errOut.String())
	}

	if !strings.Contains(out.String(), `"protocolVersion":"2024-11-05"`) {
		t.Errorf("expected initialize response in stdout, got: %s", out.String())
	}
}

func TestMCPRunner_InvalidCommand(t *testing.T) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	runner := NewMCPRunner(nil, out, errOut, "", "", "", "", "", nil)
	code := runner.Run(context.Background(), []string{"unknown"})

	if code != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput(14), got %v", code)
	}
}

// 계획 032 S2 (M1~M3, D-01): MCPRunner.Run 실제 구동 시 워커 프로세스 argv에 -net-allow 및 -verbose가 올바르게 주입되는지
// 가짜 워커 스크립트를 통해 관찰한다.
func TestMCPRunner_WorkerArgsPassthrough(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		globalDebug bool
		wantNet     bool
		wantNetArg  string
		wantVerbose bool
	}{
		{
			name:        "M1: net-allow 플래그 전달",
			args:        []string{"serve", "-net-allow", "127.0.0.1:18080"},
			globalDebug: false,
			wantNet:     true,
			wantNetArg:  "127.0.0.1:18080",
			wantVerbose: false,
		},
		{
			name:        "M2: net-allow 플래그 생략",
			args:        []string{"serve"},
			globalDebug: false,
			wantNet:     false,
			wantVerbose: false,
		},
		{
			name:        "M3: 전역 Debug 레벨 시 -verbose 전달",
			args:        []string{"serve"},
			globalDebug: true,
			wantNet:     false,
			wantVerbose: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := slog.Default()
			t.Cleanup(func() { slog.SetDefault(prev) })
			level := slog.LevelInfo
			if tc.globalDebug {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level})))

			tmpDir := t.TempDir()
			argsFile := filepath.Join(tmpDir, "worker_args.txt")

			// 가짜 워커 셸 스크립트 작성 (argv 전체를 argsFile에 한 줄씩 기록하고 정상 JSON-RPC 워커처럼 EOF까지 stdin 대기 후 종료)
			scriptPath := filepath.Join(tmpDir, "fake_worker.sh")
			scriptContent := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> %q; done\necho '{\"version\":\"1.0\",\"trace_id\":\"t\",\"exit_code\":0}'\n", argsFile)
			if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o755); err != nil {
				t.Fatalf("failed to write fake worker script: %v", err)
			}

			// tools/call 요청 프레임
			callFrame := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"test.txt"},"_meta":{"authz_token":"test-token"}}}` + "\n"
			in := strings.NewReader(callFrame)
			out := &bytes.Buffer{}
			errOut := &bytes.Buffer{}

			rig := setupPEPCLITestRig(t)
			runner := NewMCPRunner(in, out, errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath, nil)
			runner.SetWorkerBinaryPath(scriptPath)

			code := runner.Run(context.Background(), tc.args)
			if code != domain.ExitSuccess {
				t.Fatalf("expected ExitSuccess(0), got %v (stderr: %s)", code, errOut.String())
			}

			captured, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatalf("failed to read captured worker args: %v", err)
			}
			lines := strings.Split(strings.TrimSpace(string(captured)), "\n")

			hasNet := false
			var netVal string
			hasVerbose := false
			for i, line := range lines {
				if line == "-net-allow" && i+1 < len(lines) {
					hasNet = true
					netVal = lines[i+1]
				}
				if line == "-verbose" {
					hasVerbose = true
				}
			}

			if hasNet != tc.wantNet {
				t.Errorf("net-allow presence: got %v, want %v (args: %v)", hasNet, tc.wantNet, lines)
			}
			if tc.wantNet && netVal != tc.wantNetArg {
				t.Errorf("net-allow value: got %q, want %q", netVal, tc.wantNetArg)
			}
			if hasVerbose != tc.wantVerbose {
				t.Errorf("verbose presence: got %v, want %v (args: %v)", hasVerbose, tc.wantVerbose, lines)
			}
		})
	}
}
