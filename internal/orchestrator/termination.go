package orchestrator

import "authz-harness/internal/domain"

// AuditActionLimitExceeded 는 부모가 강제한 한계 초과 감사 액션이다.
const AuditActionLimitExceeded = "agent.limit_exceeded"

// Termination 은 부모가 관찰한 자식 프로세스의 종료 형태다.
type Termination string

const (
	TermExited         Termination = "exited"          // 프로세스가 스스로 종료 코드를 내고 끝남
	TermTimedOut       Termination = "timed_out"       // 부모가 Timeout 으로 그룹 종료
	TermOutputExceeded Termination = "output_exceeded" // 부모가 출력 상한으로 그룹 종료
	TermCanceled       Termination = "canceled"        // 부모 ctx 취소로 그룹 종료
	TermSignaled       Termination = "signaled"        // 부모가 강제하지 않은 신호로 종료
)

// classifyExit 는 관찰된 종료 형태로부터 표준 종료 코드와 Reason 을 도출하는 유일한 순수 함수다.
func classifyExit(term Termination, rawExit int, childReason string) (domain.ExitCode, domain.Reason) {
	switch term {
	case TermOutputExceeded:
		return domain.ExitResourceLimit, domain.ReasonResourceOutputLimit
	case TermTimedOut:
		return domain.ExitResourceLimit, domain.ReasonResourceTimeout
	case TermExited:
		if rawExit == 0 || (rawExit >= 11 && rawExit <= 16) {
			return domain.ExitCode(rawExit), domain.Reason(childReason)
		}
	}
	return domain.ExitInternalError, domain.ReasonSubprocessAbnormalExit
}
