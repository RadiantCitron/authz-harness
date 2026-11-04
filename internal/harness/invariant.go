package harness

import "fmt"

// InvariantViolation 은 종료 코드·감사로는 드러나지 않는 부가 증거(손자 프로세스 소멸,
// 버퍼 크기 등)가 깨졌음을 시나리오가 판정기에 알리는 에러 타입이다.
type InvariantViolation struct {
	Detail string
}

// Error 는 error 인터페이스를 구현한다.
func (e *InvariantViolation) Error() string {
	return "invariant violation: " + e.Detail
}

// Invariantf 는 포맷된 상세 설명으로 InvariantViolation 을 생성한다.
func Invariantf(format string, args ...any) error {
	return &InvariantViolation{Detail: fmt.Sprintf(format, args...)}
}
