package mcp

import (
	"context"
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
	if len(res.Content) != 1 || res.Content[0].Text != "token insufficient scope" {
		t.Errorf("unexpected content: %+v", res.Content)
	}
}
