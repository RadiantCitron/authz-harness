// Package pep 은 인가 집행 관문(Policy Enforcement Point) 및 다형적 도구(Tool) 실행 전략을 제공한다.
//
// [ADR 0008 도구 전략 패턴(Strategy Pattern)]
// 파이프라인 검문소 단계(input, boundary, execute, settle)는 개별 도구의 세부 구현(파일 경로인지, URL 인지, 프로세스 명령인지)을
// 일절 알지 못하며, 오직 Tool 인터페이스의 표준 메서드만을 호출한다.
// 새로운 도구를 추가할 때 게이트웨이 파이프라인(10단계 루프)을 수정할 필요 없이 Tool 인터페이스 구현체만 추가하면 된다.
package pep

import (
	"context"

	"authz-harness/internal/domain"
	"authz-harness/internal/netguard"
)

// Tool 은 특정 도구 행위(domain.Action)에 필요한 도구별 지식(입력 정규화, 경계 검사, 예산 계획, 실행)을 캡슐화한 전략 인터페이스다.
type Tool interface {
	// Prepare 는 1단계 input 검문소에서 호출되어 도구별 입력값을 정규화하고 유효성을 사전 검증한다.
	// 예: net:fetch 의 경우 호스트:포트 추출 및 URL 지문 생성.
	Prepare(c *Call) error

	// CheckBoundary 는 4단계 boundary 검문소에서 호출되어 도구별 보안 격리 경계를 검사한다.
	// 예: file 은 jail 루트 탈출 여부, net 은 allow-list 등록 여부, exec 은 커맨드 화이트리스트 일치 여부.
	CheckBoundary(c *Call) error

	// BudgetPlan 은 7단계 budget 및 10단계 settle 에서 사용할 예산 차감 및 환불 전략을 반환한다.
	BudgetPlan(c *Call) BudgetPlan

	// Execute 는 9단계 execute 검문소에서 호출되어 실제 도구 동작을 샌드박스 내에서 집행한다.
	Execute(ctx context.Context, c *Call) (Output, error)
}

// BudgetPlan 은 예산 토큰에 대한 도구별 차감 및 정산 방식을 규정하는 정책 구조체다.
// 모든 도구는 호출 1회를 budget 단계에서 공통으로 사전 차감한다.
type BudgetPlan struct {
	// ChargeWriteBytes 가 true 면 7단계 budget 에서 요청 페이로드(c.req.Data)의 바이트 수만큼 쓰기 예산을 사전 차감한다 (file:write, exec:run).
	ChargeWriteBytes bool

	// PostCharge 가 true 면 10단계 settle 에서 실제 읽어들인/수신한 출력 바이트(Output.Data)만큼 읽기 예산을 사후 정산 차감한다 (file:read, net:fetch, exec:run).
	PostCharge bool

	// RefundAfterStart 가 true 면 9단계 execute 가 시작된 뒤 실패하더라도 사전 차감했던 예산을 환불(Compensate)한다.
	// 반면 외부 부작용이 이미 발생했을 수 있는 exec:run 등은 false 로 설정하여 부분 실패 시에도 환불하지 않는다.
	RefundAfterStart bool
}

// Output 은 도구 실행(execute) 완료 후 반환되는 결과 데이터와 I/O 통계다.
type Output struct {
	// Data 는 도구가 생성하거나 읽어들인 원시 바이트 결과다 (file 읽기 내용, HTTP 응답 바디, 프로세스 stdout).
	Data []byte

	// BytesRead 는 읽어들인 바이트 수다.
	BytesRead int

	// BytesWrote 는 기록한 바이트 수다.
	BytesWrote int
}

// Call 은 단일 인가 집행 트랜잭션에서 컨베이어 벨트를 타며 누적되는 실행 컨텍스트 패킷이다.
// 설정(cfg), 불변 요청(req), 가변 파이프라인 상태(st), 도구 전용 정규화 타깃(fetchTarget)을 묶어 각 단계에 전달된다.
type Call struct {
	cfg         *Config
	req         Request
	st          *pipelineState
	fetchTarget netguard.Target // net:fetch 정규화 결과 (Prepare 가 채운다)
}

// tools 는 등록된 액션(domain.Action)을 구체 Tool 구현체로 매핑하는 고정 레지스트리 표다.
// 이 표에 없는 미등록 액션은 1단계 input 검문소에서 즉시 차단(Fail-Closed)된다.
var tools = map[domain.Action]Tool{
	domain.ActionFileRead:  fileReadTool{},
	domain.ActionFileWrite: fileWriteTool{},
	domain.ActionNetFetch:  netFetchTool{},
	domain.ActionExecRun:   execRunTool{},
}

// toolFor 는 지정된 액션에 해당하는 Tool 전략 구현체를 조회한다.
func toolFor(a domain.Action) (Tool, bool) {
	t, ok := tools[a]
	return t, ok
}
