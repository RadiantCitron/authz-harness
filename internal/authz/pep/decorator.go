package pep

import "context"

// BeforeIOHook 은 결함 주입(TOCTOU 시뮬레이션 등)을 위해 관문 실행 직전에 호출되는 훅 함수 타입이다.
type BeforeIOHook func(ctx context.Context, req Request) error

type revokeBeforeIODecorator struct {
	next Gateway
	hook BeforeIOHook
}

// Execute 는 req.InjectRevokeBeforeIO 가 참이고 hook 이 정의되어 있을 때 hook 을 먼저 실행한 후
// 본래 Gateway.Execute 를 호출한다.
func (d *revokeBeforeIODecorator) Execute(ctx context.Context, req Request) (*Result, error) {
	if req.InjectRevokeBeforeIO && d.hook != nil {
		if err := d.hook(ctx, req); err != nil {
			return &Result{
				Allowed:  false,
				ExitCode: 16,
				Reason:   "HOOK_ERROR",
				Details:  err.Error(),
			}, err
		}
	}
	return d.next.Execute(ctx, req)
}

// WithBeforeIOHook 은 기존 Gateway 를 감싸서 req.InjectRevokeBeforeIO 가 활성화되었을 때만
// 외부에서 주입된 hook 을 실행한 뒤 본래 Gateway.Execute 를 호출하는 데코레이터를 반환한다.
// 이를 통해 SubagentWorker 는 state.Store 의 존재를 전혀 알지 못한다.
func WithBeforeIOHook(next Gateway, hook BeforeIOHook) Gateway {
	return &revokeBeforeIODecorator{
		next: next,
		hook: hook,
	}
}
