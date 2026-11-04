package subagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

// SubagentWorker 는 stdin JSON 프레임을 수신하여 PEP 게이트웨이를 경유해 작업을 집행하는 서브에이전트 워커다.
// Zone B 상태 저장소(state.Store)에 대한 참조를 일절 가지지 않는 순수 위임 집행기다.
type SubagentWorker struct {
	gateway pep.Gateway
}

// NewWorker 는 PEP 게이트웨이를 주입받아 SubagentWorker 인스턴스를 생성한다.
func NewWorker(gateway pep.Gateway) (*SubagentWorker, error) {
	if gateway == nil {
		return nil, fmt.Errorf("subagent: pep gateway is required")
	}
	return &SubagentWorker{
		gateway: gateway,
	}, nil
}

// Execute 는 파싱된 요청을 바탕으로 PEP 게이트웨이를 호출하고 응답과 Exit Code를 반환한다.
// 모든 인자 검증 및 인증·인가는 PEP 단일 입출구(SESE) 게이트웨이에 위임하여 일관된 감사 로그를 보장한다.
func (w *SubagentWorker) Execute(ctx context.Context, req SubagentRequest) (SubagentResponse, int) {
	resp := SubagentResponse{
		TraceID:  req.TraceID,
		Action:   req.Action,
		FilePath: req.FilePath,
	}

	// 음수 오프셋은 만료된 토큰을 되살리는 손잡이이므로 PEP 호출 전에 거부한다 (Fail-Closed).
	if req.ClockOffsetSeconds < 0 {
		resp.ExitCode = int(domain.ExitBadInput)
		resp.Reason = string(domain.ReasonInvalidArguments)
		resp.Error = "clock_offset_sec must not be negative"
		return resp, resp.ExitCode
	}

	// PEP Gateway 요청 조립 (RequireTraceID: true로 위임하여 Gate 0에서 동일하게 차단)
	pepReq := pep.Request{
		Token:          req.Token,
		Action:         domain.Action(req.Action),
		Resource:       req.FilePath,
		Data:           []byte(req.Data),
		TraceID:        req.TraceID,
		RequireTraceID: true,
		ClockOffset:    time.Duration(req.ClockOffsetSeconds) * time.Second,
	}

	// PEP 5단계 관문 집행
	pepRes, err := w.gateway.Execute(ctx, pepReq)
	if err != nil {
		resp.ExitCode = int(domain.ExitInternalError)
		resp.Reason = "GATEWAY_ERROR"
		resp.Error = fmt.Sprintf("gateway execution error: %v", err)
		return resp, resp.ExitCode
	}

	// 결과 매핑
	resp.ExitCode = int(pepRes.ExitCode)
	resp.Reason = string(pepRes.Reason)

	if pepRes.Allowed {
		resp.BytesRead = pepRes.BytesRead
		resp.BytesWritten = pepRes.BytesWrote
		if len(pepRes.Data) > 0 {
			resp.Output = string(pepRes.Data)
		}
	} else {
		resp.Error = pepRes.Details
		if resp.Error == "" {
			resp.Error = string(pepRes.Reason)
		}
	}

	return resp, resp.ExitCode
}

// ExecuteStream 은 io.Reader(stdin)에서 JSON 프레임을 읽어 작업을 집행하고,
// io.Writer(stdout)에 JSON 응답을 기록한 뒤 프로세스 종료 코드를 반환한다.
func (w *SubagentWorker) ExecuteStream(ctx context.Context, in io.Reader, out io.Writer) int {
	var req SubagentRequest
	dec := json.NewDecoder(in)
	if err := dec.Decode(&req); err != nil {
		exitCode := int(domain.ExitBadInput)
		resp := SubagentResponse{
			ExitCode: exitCode,
			Reason:   string(domain.ReasonInvalidArguments),
			Error:    fmt.Sprintf("failed to parse json frame: %v", err),
		}
		_ = json.NewEncoder(out).Encode(resp)
		return exitCode
	}

	resp, exitCode := w.Execute(ctx, req)
	if encodeErr := json.NewEncoder(out).Encode(resp); encodeErr != nil {
		// 표준 출력 스트림 인코딩 오류
		return int(domain.ExitInternalError)
	}

	return exitCode
}
