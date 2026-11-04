package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// SubprocessExecutor 는 orchestrator.Spawner 를 통해 격리된 서브프로세스에 도구 호출을 위임하는 Executor 구현체다.
// 어댑터 프로세스 자체는 어떠한 파일 I/O나 Zone A/B 접근도 수행하지 않는다.
type SubprocessExecutor struct {
	spawner orchestrator.Spawner
}

// NewSubprocessExecutor 는 Spawner를 주입받아 SubprocessExecutor를 생성한다.
func NewSubprocessExecutor(spawner orchestrator.Spawner) *SubprocessExecutor {
	return &SubprocessExecutor{
		spawner: spawner,
	}
}

// ExecuteTool 은 파싱된 ToolCallRequest 를 subagent.SubagentRequest 로 변환하여 격리 서브프로세스에서 실행한다.
func (e *SubprocessExecutor) ExecuteTool(ctx context.Context, req *ToolCallRequest) (*ToolExecutionResult, error) {
	if e.spawner == nil {
		return nil, fmt.Errorf("spawner is not configured")
	}

	traceID := generateTraceID()

	subReq := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  traceID,
		Token:    req.AuthzToken,
		Action:   string(req.Action),
		FilePath: req.Path,
		Data:     req.Data,
	}

	spawnRes, err := e.spawner.Spawn(ctx, subReq)
	if err != nil {
		return nil, fmt.Errorf("subprocess execution failed: %w", err)
	}

	// 1. 자식 프로세스 정상 응답 수거
	if spawnRes.Response != nil {
		resp := spawnRes.Response
		if spawnRes.ExitCode == 0 {
			msg := resp.Output
			if msg == "" && req.Action == "file:write" {
				msg = fmt.Sprintf("successfully wrote %d bytes to %s", resp.BytesWritten, resp.FilePath)
			}
			return &ToolExecutionResult{
				Content: []ToolContent{
					{Type: "text", Text: sanitizeMessage(msg)},
				},
				IsError: false,
			}, nil
		}

		// 자식 프로세스 거부 응답 (ExitCode != 0): 오류 매핑 표를 통해 안전하게 정제
		return MapSubprocessError(spawnRes.ExitCode, resp.Reason, resp.Error), nil
	}

	// 2. Response 프레임 파싱 실패 시 stderr 또는 raw 에러 반환
	return MapSubprocessError(spawnRes.ExitCode, string(spawnRes.Reason), spawnRes.StderrRaw), nil
}

func generateTraceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("mcp-%d", time.Now().UnixNano())
	}
	return "mcp-" + hex.EncodeToString(b)
}
