// Package pep 은 격리된 프로세스 실행(exec:run) 도구의 Tool 인터페이스 구현을 제공한다.
//
// [프로세스 실행 가드레일 (ExecRunner) 및 부분 실패 환불 금지]
// 1. 커맨드 화이트리스트 고정:
//    - 임의의 셸 명령어 실행은 원천 차단되며, 코드에 사전 고정된 allow-list ID 만 execguard 를 통해 허용된다.
// 2. 부작용 발생 후 환불 금지 (RefundAfterStart: false):
//    - 파일 쓰기나 네트워크 읽기와 달리, 서브프로세스는 실행이 한 번 시작되면 외부 부작용(Side Effect)이 이미 발생했을 수 있다.
//    - 따라서 실행 시작 후 실패하더라도 선차감된 호출 회수 및 바이트 예산을 환불하지 않고 소진 처리한다.
package pep

import (
	"context"
	"fmt"

	"authz-harness/internal/domain"
	"authz-harness/internal/execguard"
)

// execRunTool 은 "exec:run" 액션을 처리하는 도구 전략이다.
type execRunTool struct{}

// Prepare 는 프로세스 실행 입력에 대한 추가 정규화를 수행하지 않는다.
func (execRunTool) Prepare(*Call) error { return nil }

// CheckBoundary 는 실행 파일 ID 및 인자 형식이 ExecRunner 화이트리스트에 부합하는지 경계를 검증한다.
func (execRunTool) CheckBoundary(c *Call) error {
	if c.cfg.ExecRunner == nil {
		return domain.NewError(domain.ReasonInternalError, "exec runner is not configured (fail-closed)", nil)
	}
	if err := execguard.Validate(c.st.resource, string(c.req.Data)); err != nil {
		return domain.NewError(domain.ReasonFromError(err, domain.ReasonExecNotAllowed), fmt.Sprintf("boundary stage exec rejected: %v", err), err)
	}
	return nil
}

// BudgetPlan 은 쓰기 바이트를 사전 차감하고, 출력 바이트를 사후 정산하며, 실행 시작 후에는 환불을 허용하지 않는다 (RefundAfterStart: false).
func (execRunTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{ChargeWriteBytes: true, PostCharge: true, RefundAfterStart: false}
}

// Execute 는 ExecRunner 를 통해 샌드박스 내에서 프로세스를 실행하고 stdout/stderr 결과를 Output 으로 반환한다.
func (execRunTool) Execute(ctx context.Context, c *Call) (Output, error) {
	out, err := c.cfg.ExecRunner.Run(ctx, c.st.resource, string(c.req.Data))
	if err != nil {
		return Output{}, domain.NewError(domain.ReasonFromError(err, domain.ReasonInternalError), fmt.Sprintf("pep: exec failed: %v", err), err)
	}
	return Output{Data: out, BytesRead: len(out)}, nil
}
