// Package pep 은 파일 읽기(file:read) 및 파일 쓰기(file:write) 도구의 Tool 인터페이스 구현을 제공한다.
//
// [Jail 샌드박스 경계 격리와 Fail-Closed]
// - fileReadTool 과 fileWriteTool 은 파일시스템에 직접 접근하지 않고,
//   모든 경로 해석과 I/O 를 c.cfg.Jail (internal/jail.Jail) 격리 계층에 위임한다.
// - boundary 단계에서 ResolvePath 를 호출하여 디렉터리 탈출(../)이나 악의적 심볼릭 링크가 감지되면 즉시 실패(ReasonPathViolation)를 반환한다.
package pep

import (
	"context"
	"fmt"

	"authz-harness/internal/domain"
	"authz-harness/internal/jail"
)

// resolveInJail 은 요청된 리소스 경로를 Jail 루트 기준으로 검증하고 안전한 절대 경로(safePath)를 상태에 기록한다.
func resolveInJail(c *Call, forWrite bool) error {
	safePath, jailErr := c.cfg.Jail.ResolvePath(c.st.resource, forWrite)
	if jailErr != nil {
		return domain.NewError(jail.ReasonFromError(jailErr), fmt.Sprintf("boundary stage jail path containment violated: %v", jailErr), jailErr)
	}
	c.st.safePath = safePath
	return nil
}

// fileReadTool 은 "file:read" 액션을 처리하는 도구 전략이다.
type fileReadTool struct{}

// Prepare 는 파일 읽기 입력에 대한 추가 정규화를 수행하지 않는다.
func (fileReadTool) Prepare(*Call) error { return nil }

// CheckBoundary 는 파일 경로가 Jail 루트 디렉터리 내에 안전하게 격리되어 있는지 검사한다.
func (fileReadTool) CheckBoundary(c *Call) error { return resolveInJail(c, false) }

// BudgetPlan 은 읽은 바이트를 사후 정산(PostCharge)하고, 실행 중 장애 시 환불(RefundAfterStart)하도록 설정한다.
func (fileReadTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{PostCharge: true, RefundAfterStart: true}
}

// Execute 는 Jail 을 통해 격리된 파일을 읽어들여 Output 으로 반환한다.
func (fileReadTool) Execute(_ context.Context, c *Call) (Output, error) {
	data, err := c.cfg.Jail.ReadFile(c.st.resource)
	if err != nil {
		return Output{}, domain.NewError(domain.ReasonInternalError, fmt.Sprintf("pep: failed to read file in jail: %v", err), err)
	}
	return Output{Data: data, BytesRead: len(data)}, nil
}

// fileWriteTool 은 "file:write" 액션을 처리하는 도구 전략이다.
type fileWriteTool struct{}

// Prepare 는 파일 쓰기 입력에 대한 추가 정규화를 수행하지 않는다.
func (fileWriteTool) Prepare(*Call) error { return nil }

// CheckBoundary 는 쓰기 대상 파일 경로가 Jail 루트 내에 격리되어 있는지 쓰기 권한 모드로 검사한다.
func (fileWriteTool) CheckBoundary(c *Call) error { return resolveInJail(c, true) }

// BudgetPlan 은 쓸 바이트(len(req.Data))를 사전 차감(ChargeWriteBytes)하고 실행 장애 시 환불하도록 설정한다.
func (fileWriteTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{ChargeWriteBytes: true, RefundAfterStart: true}
}

// Execute 는 Jail 을 통해 지정된 파일에 데이터를 원자적으로 기록한다.
func (fileWriteTool) Execute(_ context.Context, c *Call) (Output, error) {
	if err := c.cfg.Jail.WriteFile(c.st.resource, c.req.Data); err != nil {
		return Output{}, domain.NewError(domain.ReasonInternalError, fmt.Sprintf("pep: failed to write file in jail: %v", err), err)
	}
	return Output{BytesWrote: len(c.req.Data)}, nil
}
