package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"

	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// SubprocessExecutor 는 orchestrator.Spawner 를 통해 격리된 서브프로세스에 도구 호출을 위임하는 Executor 구현체다.
// 어댑터 프로세스 자체는 어떠한 파일 I/O나 Zone A/B 접근도 수행하지 않는다.
type SubprocessExecutor struct {
	spawner orchestrator.Spawner
	logger  *slog.Logger // nil 이면 worker stderr 를 중계하지 않는다
}

// ExecutorOption 은 SubprocessExecutor 의 선택 설정이다.
type ExecutorOption func(*SubprocessExecutor)

// WithLogger 는 worker(자식) 프로세스가 stderr 로 낸 운영 로그를 Debug 로 중계할 로거를 지정한다.
// 중계 내용의 원시 토큰 마스킹은 로거 핸들러(slogadapter.RedactReplaceAttr)가 맡는다.
func WithLogger(l *slog.Logger) ExecutorOption {
	return func(e *SubprocessExecutor) { e.logger = l }
}

// NewSubprocessExecutor 는 Spawner를 주입받아 SubprocessExecutor를 생성한다.
func NewSubprocessExecutor(spawner orchestrator.Spawner, opts ...ExecutorOption) *SubprocessExecutor {
	e := &SubprocessExecutor{
		spawner: spawner,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// ExecuteTool 은 파싱된 ToolCallRequest 를 subagent.SubagentRequest 로 변환하여 격리 서브프로세스에서 실행한다.
func (e *SubprocessExecutor) ExecuteTool(ctx context.Context, req *ToolCallRequest) (*ToolExecutionResult, error) {
	if e.spawner == nil {
		return nil, fmt.Errorf("spawner is not configured")
	}

	traceID, err := generateTraceID()
	if err != nil {
		// 난수원 고장 시 약한 대체 번호로 진행하지 않는다 (Fail-Closed, 자식 프로세스 미생성).
		return nil, fmt.Errorf("generate trace id: %w", err)
	}

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

	// worker 의 운영 로그(stderr)는 응답 프레임 파싱 성공 여부와 무관하게 Debug 로 중계한다.
	if e.logger != nil && spawnRes.StderrRaw != "" {
		e.logger.Debug("worker stderr", "trace_id", traceID, "stderr", spawnRes.StderrRaw)
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

// randRead 는 시험에서 난수원 실패를 주입하기 위한 간접 참조다 (프로덕션은 crypto/rand.Read).
var randRead = rand.Read

func generateTraceID() (string, error) {
	b := make([]byte, 8)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return "mcp-" + hex.EncodeToString(b), nil
}
