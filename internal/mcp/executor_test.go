package mcp

import (
	"context"
	"strings"
	"testing"

	"authz-harness/internal/domain"
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
