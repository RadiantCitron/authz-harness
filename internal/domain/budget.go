// Package domain 은 토큰에 부여되는 자원 소비 상한(Budget) 및 인가 관문용 최소 원장 포트 인터페이스를 정의한다.
//
// [예산 설계 원칙과 DIP 의존성 역전]
// 1. 토큰 내 상한(Budget)과 원장(Ledger)의 분리:
//    - JWT 토큰 클레임은 오직 허용된 "최대 상한(MaxCalls, MaxReadBytes, MaxWriteBytes)"만을 포함한다.
//    - 현재까지 실제로 소비된 누적량은 Zone B 디스크 원장(budget_ledger.json)에서 관리하여 동시성 제어와 정산이 이루어진다.
// 2. PEP 인가 관문용 최소 DIP 포트 (BudgetLedger):
//    - 관문(authz/pep)은 구체적인 파일 기반 원장(authn/budget.FileLedger)을 직접 알 필요 없이,
//      본 인터페이스의 Consume(차감)과 Refund(환불) 메서드만 호출한다.
//    - 이로써 authz 계층이 authn 계층의 구체 패키지에 종속되는 아키텍처 결합을 방지한다.
package domain

// Budget 은 토큰이 위임받은 소비 상한(호출 횟수, 읽기 바이트, 쓰기 바이트) 명세다.
// 바이트 한도 0 은 "한도 제한 없음"을 의미하며, 활성 한도에서 잔여량이 0 에 도달하면 "소진(Exhausted)"으로 간주된다.
type Budget struct {
	// MaxCalls 는 이 토큰으로 수행 가능한 도구 실행(execute)의 최대 허용 횟수다 (1 이상 필수).
	MaxCalls int64 `json:"max_calls"`

	// MaxReadBytes 는 file:read 도구 등을 통해 읽을 수 있는 최대 누적 바이트 수다 (0: 무제한).
	MaxReadBytes int64 `json:"max_read_bytes,omitempty"`

	// MaxWriteBytes 는 file:write 도구 등을 통해 쓸 수 있는 최대 누적 바이트 수다 (0: 무제한).
	MaxWriteBytes int64 `json:"max_write_bytes,omitempty"`
}

// BudgetLedger 는 PEP 인가 관문이 10단계 파이프라인에서 예산 토큰을 집행할 때 사용하는 최소 원장 포트(DIP Interface)다.
//
// [메서드 규약]
// - Consume: PEP 7단계(budget)에서 실행 전 호출 회수 및 예상 바이트를 선차감한다. 잔여 예산 부족 시 ReasonBudgetExhausted 에러를 반환.
// - Refund: PEP 8단계(precommit_audit) 등 후속 단계가 실패했을 때, 파이프라인 엔진의 LIFO 역순 보상(Compensate)을 통해 선차감했던 예산을 즉시 환불/복구한다.
//
// 원장 초기화, 자식 토큰 예산 예약, 파일 잠금(flock) 등 관리 기능은 authn/budget 패키지 내부에서 격리된다.
type BudgetLedger interface {
	Consume(jti string, calls, readBytes, writeBytes int64) error
	Refund(jti string, calls, readBytes, writeBytes int64) error
}

// Validate 는 MaxCalls 가 양수이고 바이트 상한들이 음수가 아님을 엄격히 검증한다.
func (b Budget) Validate() error {
	if b.MaxCalls <= 0 || b.MaxReadBytes < 0 || b.MaxWriteBytes < 0 {
		return NewError(ReasonInvalidArguments,
			"budget requires max_calls > 0 and non-negative byte limits", nil)
	}
	return nil
}

// HasReadLimit 는 읽기 바이트 한도가 활성(0보다 큼)인지 반환한다.
func (b Budget) HasReadLimit() bool { return b.MaxReadBytes > 0 }

// HasWriteLimit 는 쓰기 바이트 한도가 활성(0보다 큼)인지 반환한다.
func (b Budget) HasWriteLimit() bool { return b.MaxWriteBytes > 0 }

// Within 은 현재 예산 b 가 상위(부모) 예산 upper 의 상한 이내인지 판정하는 축소 위임 불변식 검사 함수다.
// 상위 토큰에 바이트 한도가 설정되어 있는데 자식 토큰이 0(무제한)을 요구하면 무제한 격상이므로 즉시 false 를 반환한다.
func (b Budget) Within(upper Budget) bool {
	if b.MaxCalls > upper.MaxCalls {
		return false
	}
	if upper.HasReadLimit() && (!b.HasReadLimit() || b.MaxReadBytes > upper.MaxReadBytes) {
		return false
	}
	if upper.HasWriteLimit() && (!b.HasWriteLimit() || b.MaxWriteBytes > upper.MaxWriteBytes) {
		return false
	}
	return true
}
