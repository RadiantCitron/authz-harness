package mcp

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/observe/slogadapter"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

type mockSpawner struct {
	lastReq subagent.SubagentRequest
	result  *orchestrator.SpawnResult
	err     error
}

func (m *mockSpawner) Spawn(ctx context.Context, req subagent.SubagentRequest) (*orchestrator.SpawnResult, error) {
	m.lastReq = req
	return m.result, m.err
}

func TestSubprocessExecutor_Success(t *testing.T) {
	mock := &mockSpawner{
		result: &orchestrator.SpawnResult{
			ExitCode: 0,
			Response: &subagent.SubagentResponse{
				ExitCode: 0,
				Action:   "file:read",
				FilePath: "docs/plan.txt",
				Output:   "plan contents",
			},
		},
	}

	exec := NewSubprocessExecutor(mock)
	req := &ToolCallRequest{
		ToolName:   "file_read",
		Action:     domain.ActionFileRead,
		Path:       "docs/plan.txt",
		AuthzToken: "bearer.token.jwt",
	}

	res, err := exec.ExecuteTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.IsError {
		t.Errorf("expected IsError=false, got true")
	}
	if len(res.Content) != 1 || res.Content[0].Text != "plan contents" {
		t.Errorf("unexpected content: %+v", res.Content)
	}

	// Spawner에 전달된 요청 검증
	if mock.lastReq.Action != "file:read" || mock.lastReq.FilePath != "docs/plan.txt" || mock.lastReq.Token != "bearer.token.jwt" {
		t.Errorf("unexpected subagent request: %+v", mock.lastReq)
	}
	if mock.lastReq.TraceID == "" {
		t.Errorf("expected traceID to be generated, got empty")
	}
}

func TestSubprocessExecutor_Denied(t *testing.T) {
	mock := &mockSpawner{
		result: &orchestrator.SpawnResult{
			ExitCode: 12,
			Response: &subagent.SubagentResponse{
				ExitCode: 12,
				Action:   "file:write",
				FilePath: "docs/plan.txt",
				Error:    "token insufficient scope",
				Reason:   "TOKEN_INSUFFICIENT_SCOPE",
			},
		},
	}

	exec := NewSubprocessExecutor(mock)
	req := &ToolCallRequest{
		ToolName:   "file_write",
		Action:     domain.ActionFileWrite,
		Path:       "docs/plan.txt",
		Data:       "new content",
		AuthzToken: "read.only.token",
	}

	res, err := exec.ExecuteTool(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.IsError {
		t.Errorf("expected IsError=true, got false")
	}
	if len(res.Content) != 1 || !strings.Contains(res.Content[0].Text, "token insufficient scope") {
		t.Errorf("unexpected content: %+v", res.Content)
	}
	if !strings.Contains(res.Content[0].Text, "TOKEN_INSUFFICIENT_SCOPE") {
		t.Errorf("expected TOKEN_INSUFFICIENT_SCOPE in text, got: %v", res.Content[0].Text)
	}
}

// TC-030-01/02: 강제 종료(Response 없음)에서도 스포너가 정한 Reason 이 도구 오류에 실린다.
func TestSubprocessExecutor_ResourceLimitReasonPropagation(t *testing.T) {
	jwt := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
	for _, reason := range []domain.Reason{domain.ReasonResourceTimeout, domain.ReasonResourceOutputLimit} {
		t.Run(string(reason), func(t *testing.T) {
			mock := &mockSpawner{result: &orchestrator.SpawnResult{
				ExitCode: 17, Reason: reason, StderrRaw: "killed " + jwt,
			}}
			res, err := NewSubprocessExecutor(mock).ExecuteTool(context.Background(), &ToolCallRequest{
				ToolName: "file_read", Action: domain.ActionFileRead, Path: "a.txt", AuthzToken: jwt,
			})
			if err != nil {
				t.Fatal(err)
			}
			text := res.Content[0].Text
			if !res.IsError || !strings.Contains(text, "["+string(reason)+"]") || !strings.Contains(text, "exit code 17") {
				t.Fatalf("unexpected text: %q", text)
			}
			if res.StructuredContent == nil || res.StructuredContent.ExitCode != 17 || res.StructuredContent.Reason != reason {
				t.Fatalf("unexpected structured: %+v", res.StructuredContent)
			}
			if ContainsRawToken(text) || ContainsRawToken(res.StructuredContent.Message) {
				t.Fatal("raw token leaked")
			}
		})
	}
}

// 보고서 029 후속: worker stderr 는 응답 파싱 성공 여부와 무관하게 로거로 중계되고, 토큰은 마스킹된다.
func TestSubprocessExecutor_RelaysWorkerStderr(t *testing.T) {
	const tok = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
	stderr := "level=DEBUG msg=\"pep stage entering\" stage=gate1_authn token=" + tok
	okResp := &orchestrator.SpawnResult{ExitCode: 0, StderrRaw: stderr, Response: &subagent.SubagentResponse{Action: "file:read", Output: "ok"}}

	tests := []struct {
		name      string
		logger    func(w *strings.Builder) *slog.Logger
		result    *orchestrator.SpawnResult
		wantRelay bool
	}{
		{"Debug 로거 + 정상 응답이어도 중계", func(w *strings.Builder) *slog.Logger {
			return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: slogadapter.RedactReplaceAttr}))
		}, okResp, true},
		{"Info 로거는 중계하지 않음", func(w *strings.Builder) *slog.Logger {
			return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
		}, okResp, false},
		{"stderr 가 비면 중계 없음", func(w *strings.Builder) *slog.Logger {
			return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
		}, &orchestrator.SpawnResult{ExitCode: 0, Response: okResp.Response}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			ex := NewSubprocessExecutor(&mockSpawner{result: tc.result}, WithLogger(tc.logger(&buf)))
			res, err := ex.ExecuteTool(context.Background(), &ToolCallRequest{ToolName: "file_read", Action: domain.ActionFileRead, Path: "a.txt", AuthzToken: "t"})
			if err != nil || res.IsError {
				t.Fatalf("unexpected result: err=%v res=%+v", err, res)
			}
			out := buf.String()
			if got := strings.Contains(out, "worker stderr"); got != tc.wantRelay {
				t.Fatalf("relay=%v, want %v: %q", got, tc.wantRelay, out)
			}
			if tc.wantRelay && (!strings.Contains(out, "pep stage entering") || strings.Contains(out, tok) || !strings.Contains(out, "[REDACTED_TOKEN]")) {
				t.Errorf("expected masked relay, got %q", out)
			}
		})
	}
}

func TestSubprocessExecutor_NoLoggerNoPanic(t *testing.T) {
	mock := &mockSpawner{result: &orchestrator.SpawnResult{StderrRaw: "x", Response: &subagent.SubagentResponse{Output: "ok"}}}
	if _, err := NewSubprocessExecutor(mock).ExecuteTool(context.Background(), &ToolCallRequest{Action: domain.ActionFileRead, Path: "a", AuthzToken: "t"}); err != nil {
		t.Fatal(err)
	}
}
