package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// JSON-RPC 2.0 표준 오류 코드
const (
	CodeParseError     = -32700 // 깨진 JSON
	CodeInvalidRequest = -32600 // 규격 미준수 JSON-RPC 프레임
	CodeMethodNotFound = -32601 // 미지원 method
	CodeInvalidParams  = -32602 // 잘못된 매개변수 / 스키마 위반
	CodeInternalError  = -32603 // 서버 내부 오류
)

// MCP 프로토콜 표준 메서드명
const (
	MethodInitialize = "initialize"
	MethodToolsList  = "tools/list"
	MethodToolsCall  = "tools/call"
)

// ToolExecutionResult 는 Executor 가 반환하는 실행 결과 요약이다.
type ToolExecutionResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolContent 는 MCP 결과 내 개별 컨텐츠 블록이다.
type ToolContent struct {
	Type string `json:"type"` // "text"
	Text string `json:"text"`
}

// Executor 는 검증된 도구 호출 요청을 집행하는 인터페이스다.
type Executor interface {
	ExecuteTool(ctx context.Context, req *ToolCallRequest) (*ToolExecutionResult, error)
}

// Server 는 MCP stdio JSON-RPC 2.0 서버 인스턴스다.
type Server struct {
	in       io.Reader
	out      io.Writer
	errOut   io.Writer
	executor Executor
	logger   *slog.Logger
	mu       sync.Mutex
}

// NewServer 는 MCP stdio 서버를 생성한다.
func NewServer(in io.Reader, out io.Writer, errOut io.Writer, executor Executor, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		in:       in,
		out:      out,
		errOut:   errOut,
		executor: executor,
		logger:   logger,
	}
}

// Serve 는 EOF나 ctx 종료 시까지 stdin에서 라인 단위로 프레임을 읽어 처리한다.
func (s *Server) Serve(ctx context.Context) error {
	reader := bufio.NewReader(s.in)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(line) > 0 {
					s.handleLine(ctx, line)
				}
				return nil
			}
			return err
		}

		s.handleLine(ctx, line)
	}
}

func (s *Server) handleLine(ctx context.Context, line []byte) {
	trimmed := strings.TrimSpace(string(line))
	if len(trimmed) == 0 {
		return
	}

	if len(trimmed) > MaxFrameSize {
		s.writeError(nil, CodeInvalidRequest, "frame exceeds maximum allowed size", nil)
		return
	}

	var req JSONRPCRequest
	if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
		// 깨진 JSON -> Parse Error (-32700), id는 null
		s.writeError(nil, CodeParseError, "parse error: invalid JSON", nil)
		return
	}

	// 알림(Notification) 프레임: id가 nil이면 어떠한 경우에도 응답하지 않음
	if req.ID == nil {
		s.logger.Debug("ignoring notification frame without id", "method", req.Method)
		return
	}

	if err := ValidateRequestFrame(&req); err != nil {
		s.writeError(req.ID, CodeInvalidRequest, err.Error(), nil)
		return
	}

	switch req.Method {
	case MethodInitialize:
		s.handleInitialize(req.ID)
	case MethodToolsList:
		s.handleToolsList(req.ID)
	case MethodToolsCall:
		s.handleToolsCall(ctx, req.ID, req.Params)
	default:
		s.writeError(req.ID, CodeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method), nil)
	}
}

func (s *Server) handleInitialize(id any) {
	result := map[string]any{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]string{
			"name":    "authz-harness-mcp",
			"version": "0.1.0",
		},
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
	}
	s.writeResult(id, result)
}

func (s *Server) handleToolsList(id any) {
	tools := []map[string]any{
		{
			"name":        ToolFileRead,
			"description": "격리된 워크스페이스 내의 대상 파일을 읽는다. (_meta.authz_token 필수)",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "읽을 대상 상대 파일 경로",
					},
				},
				"required":             []string{"path"},
				"additionalProperties": false,
			},
		},
		{
			"name":        ToolFileWrite,
			"description": "격리된 워크스페이스 내의 대상 파일에 내용을 쓴다. (_meta.authz_token 필수)",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "기록할 대상 상대 파일 경로",
					},
					"data": map[string]any{
						"type":        "string",
						"description": "기록할 파일 내용",
					},
				},
				"required":             []string{"path", "data"},
				"additionalProperties": false,
			},
		},
	}

	s.writeResult(id, map[string]any{
		"tools": tools,
	})
}

func (s *Server) handleToolsCall(ctx context.Context, id any, rawParams json.RawMessage) {
	toolReq, err := ParseToolCallParams(rawParams)
	if err != nil {
		// 스키마 오류, 토큰 누락, 알 수 없는 도구/인자 -> Invalid Params (-32602)
		s.writeError(id, CodeInvalidParams, err.Error(), nil)
		return
	}

	if s.executor == nil {
		s.writeError(id, CodeInternalError, "executor not configured", nil)
		return
	}

	res, execErr := s.executor.ExecuteTool(ctx, toolReq)
	if execErr != nil {
		s.writeError(id, CodeInternalError, execErr.Error(), nil)
		return
	}

	s.writeResult(id, res)
}

func (s *Server) writeResult(id any, result any) {
	resp := JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  result,
	}
	s.writeFrame(resp)
}

func (s *Server) writeError(id any, code int, message string, data any) {
	resp := JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	s.writeFrame(resp)
}

func (s *Server) writeFrame(resp JSONRPCResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(resp)
	if err != nil {
		s.logger.Error("failed to marshal jsonrpc response", "error", err)
		return
	}

	data = append(data, '\n')
	if _, err := s.out.Write(data); err != nil {
		s.logger.Error("failed to write jsonrpc response", "error", err)
	}
}
