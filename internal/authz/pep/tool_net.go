// Package pep 은 로컬 루프백 전용 HTTP 요청(net:fetch) 도구의 Tool 인터페이스 구현을 제공한다.
//
// [네트워크 송신 보안 가드레일 (NetGuard)]
// 1. 데이터 페이로드 금지:
//    - net:fetch 는 GET 요청 전용이므로 c.req.Data 가 포함되어 있으면 즉시 거부한다.
// 2. URL 지문 마스킹 (Zero Leakage):
//    - 쿼리 스트링이나 URL 내에 토큰/비밀값이 포함될 수 있으므로, 원문 URL 대신 DataDigest(t.URL) 지문만 argHash 에 기록한다.
// 3. 루프백 화이트리스트 강제:
//    - NetGuard 가 미구성되었거나 허용 목록(NetAllowList)에 없는 대상은 ReasonEgressDenied 로 즉시 차단된다.
package pep

import (
	"context"
	"fmt"

	"authz-harness/internal/domain"
	"authz-harness/internal/netguard"
)

// netFetchTool 은 "net:fetch" 액션을 처리하는 도구 전략이다.
type netFetchTool struct{}

// Prepare 는 요청 URL 을 파싱 및 정규화하고, URL 지문(argHash)을 생성하며, 페이로드 존재 여부를 검사한다.
func (netFetchTool) Prepare(c *Call) error {
	if len(c.req.Data) > 0 {
		return domain.NewError(domain.ReasonInvalidArguments, "net:fetch must not carry data", nil)
	}
	t, err := netguard.ParseTarget(c.st.resource)
	if err != nil {
		// 원문 URL(자격 정보·질의 포함 가능)이 감사에 남지 않게 지문만 기록한다.
		c.st.argHash = domain.DataDigest([]byte(c.st.resource))
		c.st.resource = "<invalid-url>"
		return domain.NewError(domain.ReasonEgressDenied, "net:fetch target rejected", err)
	}
	c.st.resource = t.HostPort
	c.fetchTarget = t
	c.st.argHash = domain.DataDigest([]byte(t.URL))
	return nil
}

// CheckBoundary 는 대상 호스트:포트가 NetGuard 화이트리스트에 부합하는지 경계를 검증한다.
func (netFetchTool) CheckBoundary(c *Call) error {
	if c.cfg.NetGuard == nil {
		return domain.NewError(domain.ReasonInternalError, "net guard is not configured (fail-closed)", nil)
	}
	if err := c.cfg.NetGuard.Check(c.st.resource); err != nil {
		return domain.NewError(domain.ReasonFromError(err, domain.ReasonEgressDenied), fmt.Sprintf("boundary stage egress denied: %v", err), err)
	}
	return nil
}

// BudgetPlan 은 수신된 바이트를 사후 정산(PostCharge)하고 실행 장애 시 환불하도록 설정한다.
func (netFetchTool) BudgetPlan(*Call) BudgetPlan {
	return BudgetPlan{PostCharge: true, RefundAfterStart: true}
}

// Execute 는 NetGuard 를 통해 HTTP GET 요청을 보내고 수신된 응답 바디를 Output 으로 반환한다.
func (netFetchTool) Execute(ctx context.Context, c *Call) (Output, error) {
	data, err := c.cfg.NetGuard.Fetch(ctx, c.fetchTarget)
	if err != nil {
		return Output{}, domain.NewError(domain.ReasonFromError(err, domain.ReasonInternalError), fmt.Sprintf("pep: net fetch failed: %v", err), err)
	}
	return Output{Data: data, BytesRead: len(data)}, nil
}
