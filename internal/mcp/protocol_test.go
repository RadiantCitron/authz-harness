package mcp

import (
	"encoding/json"
	"errors"
	"testing"

	"authz-harness/internal/domain"
)

func TestMapToolToAction(t *testing.T) {
	// TC-010-01: 도구 이름 file_read -> ActionFileRead 매핑
	actRead, err := MapToolToAction(ToolFileRead)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if actRead != domain.ActionFileRead {
		t.Errorf("expected %s, got %s", domain.ActionFileRead, actRead)
	}

	// file_write -> ActionFileWrite 매핑
	actWrite, err := MapToolToAction(ToolFileWrite)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if actWrite != domain.ActionFileWrite {
		t.Errorf("expected %s, got %s", domain.ActionFileWrite, actWrite)
	}

	// TC-010-02: 알 수 없는 도구 이름 -> ErrUnknownTool
	_, err = MapToolToAction("shell_exec")
	if !errors.Is(err, ErrUnknownTool) {
		t.Errorf("expected ErrUnknownTool, got %v", err)
	}
}

func TestValidateRequestFrame(t *testing.T) {
	tests := []struct {
		name    string
		req     JSONRPCRequest
		wantErr error
	}{
		{
			name: "정상 프레임",
			req: JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/list",
			},
			wantErr: nil,
		},
		{
			name: "jsonrpc 버전 불일치",
			req: JSONRPCRequest{
				JSONRPC: "1.0",
				ID:      1,
				Method:  "tools/list",
			},
			wantErr: ErrInvalidJSONRPC,
		},
		{
			name: "method 누락",
			req: JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "",
			},
			wantErr: ErrMissingMethod,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequestFrame(&tt.req)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParseToolCallParams(t *testing.T) {
	t.Run("정상 file_read 파싱", func(t *testing.T) {
		raw := json.RawMessage(`{
			"name": "file_read",
			"arguments": {
				"path": "docs/plan.txt"
			},
			"_meta": {
				"authz_token": "valid.jwt.token"
			}
		}`)

		req, err := ParseToolCallParams(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.ToolName != "file_read" || req.Action != domain.ActionFileRead {
			t.Errorf("unexpected tool: %v, action: %v", req.ToolName, req.Action)
		}
		if req.Path != "docs/plan.txt" {
			t.Errorf("unexpected path: %v", req.Path)
		}
		if req.AuthzToken != "valid.jwt.token" {
			t.Errorf("unexpected token: %v", req.AuthzToken)
		}
	})

	t.Run("정상 file_write 파싱", func(t *testing.T) {
		raw := json.RawMessage(`{
			"name": "file_write",
			"arguments": {
				"path": "docs/out.txt",
				"data": "hello world"
			},
			"_meta": {
				"authz_token": "valid.jwt.token"
			}
		}`)

		req, err := ParseToolCallParams(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.ToolName != "file_write" || req.Action != domain.ActionFileWrite {
			t.Errorf("unexpected tool: %v, action: %v", req.ToolName, req.Action)
		}
		if req.Path != "docs/out.txt" || req.Data != "hello world" {
			t.Errorf("unexpected path: %v, data: %v", req.Path, req.Data)
		}
	})

	// TC-010-03: file_write에 data 누락 -> 스키마 오류
	t.Run("TC-010-03: file_write에 data 누락", func(t *testing.T) {
		raw := json.RawMessage(`{
			"name": "file_write",
			"arguments": {
				"path": "docs/out.txt"
			},
			"_meta": {
				"authz_token": "valid.jwt.token"
			}
		}`)

		_, err := ParseToolCallParams(raw)
		if !errors.Is(err, ErrMissingData) {
			t.Errorf("expected ErrMissingData, got %v", err)
		}
	})

	// TC-010-04: 알 수 없는 인자 필드 포함 -> 거부
	t.Run("TC-010-04: 알 수 없는 인자 필드 포함", func(t *testing.T) {
		raw := json.RawMessage(`{
			"name": "file_read",
			"arguments": {
				"path": "docs/plan.txt",
				"extra_field": "injected"
			},
			"_meta": {
				"authz_token": "valid.jwt.token"
			}
		}`)

		_, err := ParseToolCallParams(raw)
		if !errors.Is(err, ErrUnexpectedArgument) {
			t.Errorf("expected ErrUnexpectedArgument, got %v", err)
		}
	})

	// TC-010-05: _meta.authz_token 누락 -> 거부
	t.Run("TC-010-05: _meta.authz_token 누락", func(t *testing.T) {
		raw := json.RawMessage(`{
			"name": "file_read",
			"arguments": {
				"path": "docs/plan.txt"
			}
		}`)

		_, err := ParseToolCallParams(raw)
		if !errors.Is(err, ErrMissingAuthzToken) {
			t.Errorf("expected ErrMissingAuthzToken, got %v", err)
		}
	})

	t.Run("경로(path) 누락 -> 거부", func(t *testing.T) {
		raw := json.RawMessage(`{
			"name": "file_read",
			"arguments": {},
			"_meta": {
				"authz_token": "valid.jwt.token"
			}
		}`)

		_, err := ParseToolCallParams(raw)
		if !errors.Is(err, ErrMissingPath) {
			t.Errorf("expected ErrMissingPath, got %v", err)
		}
	})
}
