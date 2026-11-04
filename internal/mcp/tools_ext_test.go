package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"authz-harness/internal/domain"
)

func callFrame(name, args string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `,"_meta":{"authz_token":"tok"}}}` + "\n"
}

// 로드맵 16 / 050 TC-050-01
func TestServer_ToolsList_FourTools(t *testing.T) {
	out := &bytes.Buffer{}
	srv := NewServer(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), out, &bytes.Buffer{}, &mockExecutor{}, nil)
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp := parseSingleResponse(t, out)
	raw, _ := json.Marshal(resp.Result)
	var res struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Required             []string `json:"required"`
				AdditionalProperties *bool    `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"file_read": "path", "file_write": "path", "net_fetch": "url", "exec_run": "command_id"}
	if len(res.Tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(res.Tools))
	}
	for _, tl := range res.Tools {
		first, ok := want[tl.Name]
		if !ok || len(tl.InputSchema.Required) == 0 || tl.InputSchema.Required[0] != first {
			t.Errorf("tool %s: bad required %v", tl.Name, tl.InputSchema.Required)
		}
		if tl.InputSchema.AdditionalProperties == nil || *tl.InputSchema.AdditionalProperties {
			t.Errorf("tool %s: additionalProperties must be false", tl.Name)
		}
		delete(want, tl.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing tools: %v", want)
	}
}

// 로드맵 16 / 050 TC-050-02
func TestServer_NewTools_InvalidParams(t *testing.T) {
	cases := []struct{ name, args string }{
		{"net_fetch", `{}`},
		{"net_fetch", `{"path":"http://127.0.0.1:1/"}`},
		{"net_fetch", `{"url":"  "}`},
		{"exec_run", `{}`},
		{"exec_run", `{"cmd":"echo-safe"}`},
		{"exec_run", `{"command_id":"echo-safe","extra":"x"}`},
		{"curl", `{"url":"http://127.0.0.1:1/"}`},
		{"file_read", `{"url":"x"}`},
	}
	for _, c := range cases {
		out := &bytes.Buffer{}
		exec := &mockExecutor{}
		srv := NewServer(strings.NewReader(callFrame(c.name, c.args)), out, &bytes.Buffer{}, exec, nil)
		if err := srv.Serve(context.Background()); err != nil {
			t.Fatal(err)
		}
		resp := parseSingleResponse(t, out)
		if resp.Error == nil || resp.Error.Code != CodeInvalidParams || exec.callCount != 0 {
			t.Errorf("%s %s: error=%v calls=%d", c.name, c.args, resp.Error, exec.callCount)
		}
	}
}

// 로드맵 16 / 050 TC-050-03
func TestParseToolCallParams_NewTools(t *testing.T) {
	req, err := ParseToolCallParams(json.RawMessage(`{"name":"net_fetch","arguments":{"url":"http://127.0.0.1:18080/s"},"_meta":{"authz_token":"t"}}`))
	if err != nil || req.Action != domain.ActionNetFetch || req.Path != "http://127.0.0.1:18080/s" || req.Data != "" {
		t.Fatalf("net_fetch: %+v %v", req, err)
	}
	req, err = ParseToolCallParams(json.RawMessage(`{"name":"exec_run","arguments":{"command_id":"echo-safe","arg":"hi"},"_meta":{"authz_token":"t"}}`))
	if err != nil || req.Action != domain.ActionExecRun || req.Path != "echo-safe" || req.Data != "hi" {
		t.Fatalf("exec_run: %+v %v", req, err)
	}
	req, err = ParseToolCallParams(json.RawMessage(`{"name":"exec_run","arguments":{"command_id":"echo-safe"},"_meta":{"authz_token":"t"}}`))
	if err != nil || req.Data != "" {
		t.Fatalf("exec_run without arg: %+v %v", req, err)
	}
	_, err = ParseToolCallParams(json.RawMessage(`{"name":"net_fetch","arguments":{},"_meta":{"authz_token":"t"}}`))
	if !errors.Is(err, ErrMissingURL) {
		t.Fatalf("expected ErrMissingURL, got %v", err)
	}
	_, err = ParseToolCallParams(json.RawMessage(`{"name":"exec_run","arguments":{},"_meta":{"authz_token":"t"}}`))
	if !errors.Is(err, ErrMissingCommandID) {
		t.Fatalf("expected ErrMissingCommandID, got %v", err)
	}
}

// 서버 경유 정상 호출: 실행기가 받은 요청과 응답 텍스트 확인.
func TestServer_NewTools_Success(t *testing.T) {
	for _, c := range []struct{ name, args, path, data string }{
		{"net_fetch", `{"url":"http://127.0.0.1:1/x"}`, "http://127.0.0.1:1/x", ""},
		{"exec_run", `{"command_id":"echo-safe","arg":"a"}`, "echo-safe", "a"},
	} {
		out := &bytes.Buffer{}
		exec := &mockExecutor{resp: &ToolExecutionResult{Content: []ToolContent{{Type: "text", Text: "OUT"}}}}
		srv := NewServer(strings.NewReader(callFrame(c.name, c.args)), out, &bytes.Buffer{}, exec, nil)
		if err := srv.Serve(context.Background()); err != nil {
			t.Fatal(err)
		}
		resp := parseSingleResponse(t, out)
		raw, _ := json.Marshal(resp.Result)
		if resp.Error != nil || !strings.Contains(string(raw), "OUT") || exec.callCount != 1 || exec.lastReq.Path != c.path || exec.lastReq.Data != c.data {
			t.Errorf("%s: err=%v result=%s req=%+v", c.name, resp.Error, raw, exec.lastReq)
		}
	}
}
