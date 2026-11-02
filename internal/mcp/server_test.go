package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type mockExecutor struct {
	callCount int
	lastReq   *ToolCallRequest
	resp      *ToolExecutionResult
	err       error
}

func (m *mockExecutor) ExecuteTool(ctx context.Context, req *ToolCallRequest) (*ToolExecutionResult, error) {
	m.callCount++
	m.lastReq = req
	return m.resp, m.err
}

func parseSingleResponse(t *testing.T, out *bytes.Buffer) JSONRPCResponse {
	t.Helper()
	var resp JSONRPCResponse
	line, err := out.ReadBytes('\n')
	if err != nil {
		t.Fatalf("failed to read response line: %v", err)
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v, raw: %s", err, string(line))
	}
	return resp
}

func TestServer_Initialize(t *testing.T) {
	// TC-020-01: initialize 요청 시 서버 정보 및 tools capability 반환
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	in := strings.NewReader(input)
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	exec := &mockExecutor{}
	srv := NewServer(in, out, errOut, exec, nil)

	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("unexpected serve error: %v", err)
	}

	resp := parseSingleResponse(t, out)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.ID != float64(1) {
		t.Errorf("expected id 1, got %v", resp.ID)
	}

	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not map: %v", resp.Result)
	}
	caps, ok := resMap["capabilities"].(map[string]any)
	if !ok || caps["tools"] == nil {
		t.Errorf("missing tools capability: %v", resMap)
	}
	info, ok := resMap["serverInfo"].(map[string]any)
	if !ok || info["name"] != "authz-harness-mcp" {
		t.Errorf("unexpected serverInfo: %v", info)
	}
}

func TestServer_ToolsList(t *testing.T) {
	// TC-020-02: tools/list 요청 시 정확히 2종 도구(file_read, file_write) 반환
	input := `{"jsonrpc":"2.0","id":"req-2","method":"tools/list"}` + "\n"
	in := strings.NewReader(input)
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	exec := &mockExecutor{}
	srv := NewServer(in, out, errOut, exec, nil)

	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("unexpected serve error: %v", err)
	}

	resp := parseSingleResponse(t, out)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.ID != "req-2" {
		t.Errorf("expected id req-2, got %v", resp.ID)
	}

	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not map: %v", resp.Result)
	}
	tools, ok := resMap["tools"].([]any)
	if !ok {
		t.Fatalf("tools is not slice: %v", resMap)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	toolNames := []string{}
	for _, tool := range tools {
		m := tool.(map[string]any)
		toolNames = append(toolNames, m["name"].(string))
	}
	if toolNames[0] != "file_read" || toolNames[1] != "file_write" {
		t.Errorf("unexpected tool names: %v", toolNames)
	}
}

func TestServer_ToolsCall_Success(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"report.txt"},"_meta":{"authz_token":"test-token"}}}` + "\n"
	in := strings.NewReader(input)
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	exec := &mockExecutor{
		resp: &ToolExecutionResult{
			Content: []ToolContent{
				{Type: "text", Text: "file content here"},
			},
		},
	}
	srv := NewServer(in, out, errOut, exec, nil)

	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("unexpected serve error: %v", err)
	}

	resp := parseSingleResponse(t, out)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if exec.callCount != 1 {
		t.Fatalf("expected executor call count 1, got %d", exec.callCount)
	}
	if exec.lastReq.Path != "report.txt" || exec.lastReq.AuthzToken != "test-token" {
		t.Errorf("unexpected request passed to executor: %+v", exec.lastReq)
	}
}

func TestServer_NegativeScenarios(t *testing.T) {
	// TC-020-03: 깨진 JSON -> -32700, 집행기 호출 0회
	t.Run("TC-020-03: 깨진 JSON", func(t *testing.T) {
		input := `{"jsonrpc": "2.0", broken json` + "\n"
		in := strings.NewReader(input)
		out := &bytes.Buffer{}
		exec := &mockExecutor{}
		srv := NewServer(in, out, &bytes.Buffer{}, exec, nil)

		if err := srv.Serve(context.Background()); err != nil {
			t.Fatalf("serve error: %v", err)
		}

		resp := parseSingleResponse(t, out)
		if resp.Error == nil || resp.Error.Code != CodeParseError {
			t.Errorf("expected CodeParseError (-32700), got %v", resp.Error)
		}
		if exec.callCount != 0 {
			t.Errorf("executor should not be called, got %d", exec.callCount)
		}
	})

	// TC-020-04: 미지원 method -> -32601
	t.Run("TC-020-04: 미지원 method", func(t *testing.T) {
		input := `{"jsonrpc":"2.0","id":100,"method":"resources/read","params":{}}` + "\n"
		in := strings.NewReader(input)
		out := &bytes.Buffer{}
		exec := &mockExecutor{}
		srv := NewServer(in, out, &bytes.Buffer{}, exec, nil)

		if err := srv.Serve(context.Background()); err != nil {
			t.Fatalf("serve error: %v", err)
		}

		resp := parseSingleResponse(t, out)
		if resp.Error == nil || resp.Error.Code != CodeMethodNotFound {
			t.Errorf("expected CodeMethodNotFound (-32601), got %v", resp.Error)
		}
		if exec.callCount != 0 {
			t.Errorf("executor should not be called, got %d", exec.callCount)
		}
	})

	// TC-020-05: 스키마 위반 tools/call -> -32602, 집행기 호출 0회
	t.Run("TC-020-05: 스키마 위반 tools/call (알 수 없는 인자)", func(t *testing.T) {
		input := `{"jsonrpc":"2.0","id":200,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"a.txt","unexpected":true},"_meta":{"authz_token":"tok"}}}` + "\n"
		in := strings.NewReader(input)
		out := &bytes.Buffer{}
		exec := &mockExecutor{}
		srv := NewServer(in, out, &bytes.Buffer{}, exec, nil)

		if err := srv.Serve(context.Background()); err != nil {
			t.Fatalf("serve error: %v", err)
		}

		resp := parseSingleResponse(t, out)
		if resp.Error == nil || resp.Error.Code != CodeInvalidParams {
			t.Errorf("expected CodeInvalidParams (-32602), got %v", resp.Error)
		}
		if exec.callCount != 0 {
			t.Errorf("executor should not be called, got %d", exec.callCount)
		}
	})

	// 토큰 누락 tools/call -> -32602
	t.Run("토큰 누락 tools/call", func(t *testing.T) {
		input := `{"jsonrpc":"2.0","id":201,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"a.txt"}}}` + "\n"
		in := strings.NewReader(input)
		out := &bytes.Buffer{}
		exec := &mockExecutor{}
		srv := NewServer(in, out, &bytes.Buffer{}, exec, nil)

		if err := srv.Serve(context.Background()); err != nil {
			t.Fatalf("serve error: %v", err)
		}

		resp := parseSingleResponse(t, out)
		if resp.Error == nil || resp.Error.Code != CodeInvalidParams {
			t.Errorf("expected CodeInvalidParams (-32602), got %v", resp.Error)
		}
		if exec.callCount != 0 {
			t.Errorf("executor should not be called, got %d", exec.callCount)
		}
	})

	// TC-020-06: 알림 프레임(id 없음) -> 응답 없음
	t.Run("TC-020-06: 알림 프레임(id 없음)", func(t *testing.T) {
		input := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}` + "\n"
		in := strings.NewReader(input)
		out := &bytes.Buffer{}
		exec := &mockExecutor{}
		srv := NewServer(in, out, &bytes.Buffer{}, exec, nil)

		if err := srv.Serve(context.Background()); err != nil {
			t.Fatalf("serve error: %v", err)
		}

		if out.Len() != 0 {
			t.Errorf("expected 0 bytes output for notification, got: %s", out.String())
		}
	})
}
