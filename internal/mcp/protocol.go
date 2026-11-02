package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"authz-harness/internal/domain"
)

// 프로토콜 및 도구 식별자 상수
const (
	JSONRPCVersion = "2.0"

	// 도구 식별자 (MCP Tool Name)
	ToolFileRead  = "file_read"
	ToolFileWrite = "file_write"

	// 최대 요청 프레임 크기 (1MB)
	MaxFrameSize = 1024 * 1024
)

// 프로토콜 및 유효성 검증 표준 에러 정의
var (
	ErrUnknownTool        = errors.New("mcp: unknown tool")
	ErrMissingAuthzToken  = errors.New("mcp: missing _meta.authz_token in params")
	ErrInvalidJSONRPC     = errors.New("mcp: invalid jsonrpc version (must be 2.0)")
	ErrMissingMethod      = errors.New("mcp: missing method")
	ErrMissingPath        = errors.New("mcp: missing required argument 'path'")
	ErrMissingData        = errors.New("mcp: missing required argument 'data' for file_write")
	ErrUnexpectedArgument = errors.New("mcp: unexpected argument in tool parameters")
	ErrFrameTooLarge      = errors.New("mcp: frame exceeds maximum allowed size")
)

// JSONRPCRequest 는 MCP stdio 프로토콜의 표준 JSON-RPC 2.0 요청 프레임이다.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse 는 MCP stdio 프로토콜의 표준 JSON-RPC 2.0 응답 프레임이다.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError 는 JSON-RPC 2.0 표준 오류 객체다.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ToolCallParams 는 tools/call 메서드의 파라미터 프레임이다.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Meta      *CallMeta       `json:"_meta,omitempty"`
}

// CallMeta 는 도구 호출 시 동반되는 메타데이터 컨텍스트로, 인증/인가 토큰을 포함한다.
type CallMeta struct {
	AuthzToken string `json:"authz_token"`
}

// ToolCallRequest 는 tools/call 요청을 파싱하여 도메인 액션 및 인자로 정규화한 구조체다.
type ToolCallRequest struct {
	ToolName   string
	Action     domain.Action
	Path       string
	Data       string
	AuthzToken string
}

// ValidateRequestFrame 은 기본 JSON-RPC 프레임의 규격 준수 여부를 검사한다.
func ValidateRequestFrame(req *JSONRPCRequest) error {
	if req.JSONRPC != JSONRPCVersion {
		return ErrInvalidJSONRPC
	}
	if strings.TrimSpace(req.Method) == "" {
		return ErrMissingMethod
	}
	return nil
}

// MapToolToAction 은 MCP 도구명을 시스템 내부 domain.Action 으로 사상한다.
func MapToolToAction(toolName string) (domain.Action, error) {
	switch toolName {
	case ToolFileRead:
		return domain.ActionFileRead, nil
	case ToolFileWrite:
		return domain.ActionFileWrite, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnknownTool, toolName)
	}
}

// ParseToolCallParams 는 tools/call 의 raw params 를 파싱하고 스키마 및 토큰을 엄격히 검증한다.
// 알 수 없는 인자(unknown fields)가 존재하거나 필수 필드가 누락된 경우 Fail-Closed 원칙에 따라 거부한다.
func ParseToolCallParams(raw json.RawMessage) (*ToolCallRequest, error) {
	if len(raw) == 0 {
		return nil, errors.New("mcp: empty tool call params")
	}

	var params ToolCallParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("mcp: invalid tool call params format: %w", err)
	}

	// 1. 도구 화이트리스트 검증
	action, err := MapToolToAction(params.Name)
	if err != nil {
		return nil, err
	}

	// 2. 토큰 전달 경로 검증 (_meta.authz_token 필수)
	if params.Meta == nil || strings.TrimSpace(params.Meta.AuthzToken) == "" {
		return nil, ErrMissingAuthzToken
	}

	// 3. 인자 스키마 엄격 검증 (DisallowUnknownFields)
	decoder := json.NewDecoder(strings.NewReader(string(params.Arguments)))
	decoder.DisallowUnknownFields()

	var args struct {
		Path *string `json:"path"`
		Data *string `json:"data"`
	}

	if err := decoder.Decode(&args); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnexpectedArgument, err)
	}

	if args.Path == nil || strings.TrimSpace(*args.Path) == "" {
		return nil, ErrMissingPath
	}

	var dataVal string
	if action == domain.ActionFileWrite {
		if args.Data == nil {
			return nil, ErrMissingData
		}
		dataVal = *args.Data
	}

	return &ToolCallRequest{
		ToolName:   params.Name,
		Action:     action,
		Path:       *args.Path,
		Data:       dataVal,
		AuthzToken: params.Meta.AuthzToken,
	}, nil
}
