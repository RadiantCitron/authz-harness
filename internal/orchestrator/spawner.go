package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
	"authz-harness/internal/subagent"
)

// SpawnConfig 는 서브에이전트 자식 프로세스 실행에 필요한 설정이다.
type SpawnConfig struct {
	BinaryPath string       // 실행할 바이너리 경로 (기본: os.Executable())
	Args       []string     // 명령행 인자 (주의: 토큰 노출 금지)
	Limits     Limits       // 자원·수명 한계 (영값은 기본값으로 정규화)
	Audit      audit.Writer // 부모 감사 로거 (선택적)
	ExtraEnv   []string     // 추가 안전 환경변수 (선택적)
}

// SpawnResult 는 자식 프로세스 실행 후 수거된 결과다.
type SpawnResult struct {
	TraceID   string                     `json:"trace_id"`
	ExitCode  int                        `json:"exit_code"`
	Response  *subagent.SubagentResponse `json:"response,omitempty"`
	StdoutRaw string                     `json:"stdout_raw,omitempty"`
	StderrRaw string                     `json:"stderr_raw,omitempty"`
	Duration  time.Duration              `json:"duration"`
	TimedOut  bool                       `json:"timed_out"`

	Termination Termination   `json:"termination"`
	Reason      domain.Reason `json:"reason,omitempty"`
	RawExitCode int           `json:"raw_exit_code"`
	Signal      string        `json:"signal,omitempty"`
}

// Spawner 는 서브에이전트 자식 프로세스를 생성하고 제어하는 인터페이스다.
type Spawner interface {
	// Spawn 은 독립 OS 자식 프로세스를 실행하고 stdin으로 요청을 주입한 뒤 결과를 수거한다.
	Spawn(ctx context.Context, req subagent.SubagentRequest) (*SpawnResult, error)
}

// SubprocessSpawner 는 os/exec 기반의 Spawner 구현체다.
type SubprocessSpawner struct {
	cfg SpawnConfig
}

// NewSubprocessSpawner 는 새로운 SubprocessSpawner 인스턴스를 반환한다.
func NewSubprocessSpawner(cfg SpawnConfig) (*SubprocessSpawner, error) {
	if cfg.BinaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get current executable: %w", err)
		}
		cfg.BinaryPath = exe
	}
	limits, err := cfg.Limits.Normalize()
	if err != nil {
		return nil, err
	}
	cfg.Limits = limits
	return &SubprocessSpawner{cfg: cfg}, nil
}

// Spawn 은 독립 OS 자식 프로세스를 실행하고 stdin으로 요청을 주입한 뒤 결과를 수거한다.
func (s *SubprocessSpawner) Spawn(ctx context.Context, req subagent.SubagentRequest) (*SpawnResult, error) {
	if req.TraceID == "" {
		return nil, errors.New("trace_id is required")
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subagent request: %w", err)
	}

	// 1. 부모 사전 감사 이벤트 (ORCHESTRATE_SPAWN)
	if s.cfg.Audit != nil {
		if err := s.cfg.Audit.Log(audit.Event{
			Timestamp: time.Now(),
			TraceID:   req.TraceID,
			Step:      "ORCHESTRATE_SPAWN",
			Actor:     "orchestrator",
			Action:    req.Action,
			Resource:  req.FilePath,
			Success:   true,
			Metadata: map[string]interface{}{
				"binary": s.cfg.BinaryPath,
			},
		}); err != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "orchestrator_spawn", "failed to record pre-spawn audit log", err)
		}
	}

	// 2. 실행 컨텍스트 및 프로세스 조립
	execCtx, cancel := context.WithTimeout(ctx, s.cfg.Limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, s.cfg.BinaryPath, s.cfg.Args...)
	cmd.Env = SanitizeEnv(os.Environ(), s.cfg.ExtraEnv...)
	configureProcessGroup(cmd, s.cfg.Limits.WaitDelay)

	// stdin 단일 프레임 주입
	cmd.Stdin = bytes.NewReader(reqBytes)

	// stdout, stderr 상한 버퍼 바인딩 (초과 시 execCtx 취소 → 그룹 SIGKILL)
	stdoutBuf := newLimitedBuffer(s.cfg.Limits.MaxOutputBytes, cancel)
	stderrBuf := newLimitedBuffer(s.cfg.Limits.MaxOutputBytes, cancel)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	startTime := time.Now()
	_ = cmd.Run() // 종료 형태는 아래에서 관찰된 사실(버퍼·ctx·ProcessState)로만 판정한다.
	duration := time.Since(startTime)

	// 종료 형태 관찰 (순서 중요: 출력 초과가 그룹 SIGKILL 을 일으키므로 먼저 본다)
	term := TermExited
	rawExit := -1
	signal := ""
	if ps := cmd.ProcessState; ps != nil {
		rawExit = ps.ExitCode()
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			signal = ws.Signal().String()
		}
	}
	switch {
	case stdoutBuf.Exceeded() || stderrBuf.Exceeded():
		term = TermOutputExceeded
	case errors.Is(execCtx.Err(), context.DeadlineExceeded):
		term = TermTimedOut
	case errors.Is(ctx.Err(), context.Canceled):
		term = TermCanceled
	case signal != "":
		term = TermSignaled
	}

	result := &SpawnResult{
		TraceID:     req.TraceID,
		StdoutRaw:   stdoutBuf.String(),
		StderrRaw:   stderrBuf.String(),
		Duration:    duration,
		Termination: term,
		RawExitCode: rawExit,
		Signal:      signal,
		TimedOut:    term == TermTimedOut,
	}

	// stdout 프레임 파싱 (자진 종료한 자식만)
	childReason := ""
	if term == TermExited && stdoutBuf.Len() > 0 {
		var resp subagent.SubagentResponse
		if err := json.Unmarshal(stdoutBuf.Bytes(), &resp); err == nil {
			result.Response = &resp
			childReason = resp.Reason
		}
	}

	exitCode, reason := classifyExit(term, rawExit, childReason)
	result.ExitCode = int(exitCode)
	result.Reason = reason

	// 3. 부모 사후 감사 이벤트 (단일 지점)
	if s.cfg.Audit != nil {
		ev := audit.Event{
			Timestamp: time.Now(),
			TraceID:   req.TraceID,
			Actor:     "orchestrator",
			Action:    req.Action,
			Resource:  req.FilePath,
			Success:   result.ExitCode == 0,
			Metadata: map[string]interface{}{
				"exit_code":   result.ExitCode,
				"duration_ms": duration.Milliseconds(),
				"termination": string(term),
			},
		}
		if exitCode == domain.ExitResourceLimit {
			ev.Step = "ORCHESTRATE_LIMIT_EXCEEDED"
			ev.Action = AuditActionLimitExceeded
			ev.Decision = "deny"
			ev.Reason = string(reason)
			ev.Success = false
		} else {
			ev.Step = "ORCHESTRATE_COLLECT"
			ev.Metadata["timed_out"] = result.TimedOut
			ev.Metadata["raw_exit_code"] = rawExit
			if signal != "" {
				ev.Metadata["signal"] = signal
			}
		}
		if err := s.cfg.Audit.Log(ev); err != nil {
			return nil, domain.NewError(domain.ReasonAuditLogFailed, "orchestrator_collect", "failed to record post-spawn audit log", err)
		}
	}

	return result, nil
}
