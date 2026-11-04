package catalog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/mcp"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// offsetSpawner 는 모든 Spawn 요청 프레임에 현재 누적 시계 오프셋을 실어 보내는 데코레이터다.
// MCP 클라이언트(tools/call 인자)는 오프셋을 줄 수 없고, 시간 시뮬레이션은 하네스의 일이다.
type offsetSpawner struct {
	next   orchestrator.Spawner
	offset func() time.Duration
}

func (o *offsetSpawner) Spawn(ctx context.Context, req subagent.SubagentRequest) (*orchestrator.SpawnResult, error) {
	req.ClockOffsetSeconds = int64(o.offset() / time.Second)
	return o.next.Spawn(ctx, req)
}

// SessionDriver 는 하나의 MCP 세션(io.Pipe 단일 서버)에서 다회 호출과 상태 변화를 구동한다.
// 시간이 흐르는 자리는 이 드라이버의 누적 offset 하나다.
type SessionDriver struct {
	env   *harness.SandboxEnvironment
	stack *harnessStack

	mu     sync.Mutex
	offset time.Duration
	seq    int
	offStk *harnessStack // 오프셋 스택(캐시, offset 변경 시 폐기)
	offFor time.Duration

	inW    *io.PipeWriter
	outR   *bufio.Reader
	outRaw *io.PipeReader
	done   chan struct{}
	errBuf *bytes.Buffer
	closed bool
}

// NewSessionDriver 는 기본 스택 위에 세션 서버 고루틴을 띄운다.
func NewSessionDriver(ctx context.Context, env *harness.SandboxEnvironment, stack *harnessStack) (*SessionDriver, error) {
	base, err := newMCPSpawner(env, stack)
	if err != nil {
		return nil, fmt.Errorf("session spawner: %w", err)
	}
	d := &SessionDriver{env: env, stack: stack, done: make(chan struct{}), errBuf: &bytes.Buffer{}}
	spawner := &offsetSpawner{next: base, offset: d.currentOffset}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	d.inW, d.outRaw, d.outR = inW, outR, bufio.NewReader(outR)

	server := mcp.NewServer(inR, outW, d.errBuf, mcp.NewSubprocessExecutor(spawner), nil)
	go func() {
		defer close(d.done)
		_ = server.Serve(ctx)
		_ = outW.Close()
	}()
	return d, nil
}

func (d *SessionDriver) currentOffset() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.offset
}

// Offset 은 누적 시계 오프셋을 반환한다.
func (d *SessionDriver) Offset() time.Duration { return d.currentOffset() }

// CallTool 은 세션에 tools/call 1건을 보내고 응답 1줄을 읽는다.
func (d *SessionDriver) CallTool(toolName string, args map[string]any, tokenVal string) (domain.ExitCode, *mcp.JSONRPCResponse, error) {
	d.mu.Lock()
	d.seq++
	id := fmt.Sprintf("session-call-%d", d.seq)
	d.mu.Unlock()

	frame, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{
			"name": toolName, "arguments": args,
			"_meta": map[string]any{"authz_token": tokenVal},
		},
	})
	if err != nil {
		return domain.ExitInternalError, nil, err
	}
	if _, err := d.inW.Write(append(frame, '\n')); err != nil {
		return domain.ExitInternalError, nil, fmt.Errorf("session write: %w", err)
	}
	line, err := d.outR.ReadBytes('\n')
	if err != nil {
		return domain.ExitInternalError, nil, fmt.Errorf("no output from mcp server: %w (stderr: %s)", err, d.errBuf.String())
	}
	var resp mcp.JSONRPCResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return domain.ExitInternalError, nil, fmt.Errorf("invalid jsonrpc response: %w", err)
	}
	code, err := exitCodeFromResponse(&resp)
	return code, &resp, err
}

// AdvanceClock 은 세션 시간을 앞으로 전진시킨다. 음수는 만료 토큰 부활 손잡이이므로 거부한다.
func (d *SessionDriver) AdvanceClock(delta time.Duration) error {
	if delta < 0 {
		return errors.New("session: negative clock advance is not allowed")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.offset += delta
	return nil
}

// RevokeGrant 는 Grant 를 회수한다.
func (d *SessionDriver) RevokeGrant(ctx context.Context, grantID string) error {
	_, err := d.stack.PAP.RevokeGrant(ctx, grantID)
	return err
}

// BumpEpoch 는 주체의 Epoch 를 올린다.
func (d *SessionDriver) BumpEpoch(ctx context.Context, subject string) (domain.Epoch, error) {
	return d.stack.PAP.BumpEpoch(ctx, subject)
}

// RotateKey 는 서명 키를 회전한다.
func (d *SessionDriver) RotateKey() error {
	_, err := d.stack.KeyManager.RotateKey(domain.AuditContext{TraceID: "session-rotate", Actor: "session"})
	return err
}

// RevokeKey 는 kid 의 키를 폐기한다.
func (d *SessionDriver) RevokeKey(kid string) error {
	return d.stack.KeyManager.RevokeKey(kid, domain.AuditContext{TraceID: "session-revoke-key", Actor: "session"})
}

// Stack 은 현재 오프셋 시각으로 동작하는 스택을 반환한다(오프셋 0이면 기본 스택).
// 재교환·발급은 이 스택으로 수행한다. 만든 스택은 Close 에서 닫는다.
func (d *SessionDriver) Stack() (*harnessStack, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.offset == 0 {
		return d.stack, nil
	}
	if d.offStk != nil && d.offFor == d.offset {
		return d.offStk, nil
	}
	if d.offStk != nil {
		_ = d.offStk.Close()
		d.offStk = nil
	}
	st, err := setupHarnessStackWithClock(d.env, domain.NewOffsetClock(d.env.MockClock, d.offset))
	if err != nil {
		return nil, fmt.Errorf("session offset stack: %w", err)
	}
	d.offStk, d.offFor = st, d.offset
	return st, nil
}

// Close 는 입력 파이프를 닫아 서버를 EOF 로 끝내고 고루틴 종료를 기다린다.
func (d *SessionDriver) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	off := d.offStk
	d.offStk = nil
	d.mu.Unlock()

	_ = d.inW.Close()
	<-d.done
	_ = d.outRaw.Close()
	if off != nil {
		return off.Close()
	}
	return nil
}
