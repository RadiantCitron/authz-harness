// Package orchestrator 는 자식 프로세스의 종료 형태 및 도메인 사유 매핑을 제공한다.
package orchestrator

import "authz-harness/internal/domain"

// AuditActionLimitExceeded 는 부모가 강제한 한계 초과 감사 액션이다.
const AuditActionLimitExceeded = "agent.limit_exceeded"

// AuditActionAgentConfined 는 스폰 시점의 OS 격리 적용(또는 적용 불가) 감사 액션이다.
// 커널 차단 여부는 기록하지 않는다 (부모가 알 수 없음).
const AuditActionAgentConfined = "agent.confined"

// Termination 은 부모가 관찰한 자식 프로세스의 종료 형태다.
type Termination string

const (
	// TermExited 는 프로세스가 스스로 정상/비정상 종료 코드를 내고 끝남을 의미한다.
	TermExited Termination = "exited"

	// TermTimedOut 은 부모가 Timeout 한계 초과로 그룹을 종료시켰음을 의미한다.
	TermTimedOut Termination = "timed_out"

	// TermOutputExceeded 는 부모가 stdout/stderr 출력 상한 초과로 그룹을 종료시켰음을 의미한다.
	TermOutputExceeded Termination = "output_exceeded"

	// TermCanceled 는 상위 부모 컨텍스트 취소로 인해 그룹이 종료되었음을 의미한다.
	TermCanceled Termination = "canceled"

	// TermSignaled 는 부모가 의도하지 않은 외부 시그널로 종료되었음을 의미한다.
	TermSignaled Termination = "signaled"
)

// classifyExit 는 관찰된 종료 형태로부터 표준 종료 코드와 domain.Reason 을 도출하는 유일한 순수 함수다.
func classifyExit(term Termination, rawExit int, childReason string) (domain.ExitCode, domain.Reason) {
	switch term {
	case TermOutputExceeded:
		return domain.ExitResourceLimit, domain.ReasonResourceOutputLimit
	case TermTimedOut:
		return domain.ExitResourceLimit, domain.ReasonResourceTimeout
	case TermExited:
		if rawExit == 0 || (rawExit >= 11 && rawExit <= 16) || rawExit == int(domain.ExitApprovalRequired) {
			return domain.ExitCode(rawExit), domain.Reason(childReason)
		}
	}
	return domain.ExitInternalError, domain.ReasonSubprocessAbnormalExit
}
