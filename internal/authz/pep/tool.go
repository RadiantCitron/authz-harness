package pep

import (
	"context"

	"authz-harness/internal/domain"
	"authz-harness/internal/netguard"
)

// Tool 은 행동(domain.Action) 하나의 도구별 지식을 모은 전략이다(ADR 0008 2장 4번).
// 단계 함수는 도구를 모르고 이 인터페이스만 부른다.
type Tool interface {
	Prepare(c *Call) error                                // 입력 정규화 (input)
	CheckBoundary(c *Call) error                          // 도구별 경계 (boundary)
	BudgetPlan(c *Call) BudgetPlan                        // 예산 차감 방식
	Execute(ctx context.Context, c *Call) (Output, error) // 실제 수행 (execute)
}

// BudgetPlan 은 예산 토큰에 대한 도구별 차감 방식이다. 호출 1회는 모든 도구가 budget 단계에서 사전 차감한다.
// ChargeWriteBytes 는 budget 에서 요청 데이터 바이트도 차감하는지,
// PostCharge 는 settle 에서 출력 바이트를 정산하는지,
// RefundAfterStart 는 실행이 시작된 뒤 실패해도 사전 차감분을 환급하는지다.
type BudgetPlan struct {
	ChargeWriteBytes bool
	PostCharge       bool
	RefundAfterStart bool
}

// Output 은 도구 실행 결과다.
type Output struct {
	Data       []byte
	BytesRead  int
	BytesWrote int
}

// Call 은 한 번의 집행 요청에서 도구가 보는 값이다. 설정과 요청, 진행 상태를 묶는다.
type Call struct {
	cfg         *Config
	req         Request
	st          *pipelineState
	fetchTarget netguard.Target // net:fetch 정규화 결과 (Prepare 가 채운다)
}

// tools 는 행동에서 도구로 가는 고정 표다. 표에 없는 행동은 input 에서 거부한다(Fail-Closed).
var tools = map[domain.Action]Tool{
	domain.ActionFileRead:  fileReadTool{},
	domain.ActionFileWrite: fileWriteTool{},
	domain.ActionNetFetch:  netFetchTool{},
	domain.ActionExecRun:   execRunTool{},
}

func toolFor(a domain.Action) (Tool, bool) {
	t, ok := tools[a]
	return t, ok
}
