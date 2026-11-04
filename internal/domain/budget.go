package domain

// Budget 은 토큰이 위임하는 소비 상한(호출 횟수·읽기 바이트·쓰기 바이트)이다.
// 토큰은 상한만 담고 실제 소비량은 Zone B 예산 원장이 관리한다.
// 바이트 한도 0 은 "한도 없음"이며, 활성 한도에서 소비 후 잔여 0 은 "소진"이다.
type Budget struct {
	MaxCalls      int64 `json:"max_calls"`
	MaxReadBytes  int64 `json:"max_read_bytes,omitempty"`
	MaxWriteBytes int64 `json:"max_write_bytes,omitempty"`
}

// Validate 는 MaxCalls > 0 이고 바이트 한도가 음수가 아님을 검증한다.
func (b Budget) Validate() error {
	if b.MaxCalls <= 0 || b.MaxReadBytes < 0 || b.MaxWriteBytes < 0 {
		return NewError(ReasonInvalidArguments, "domain_budget",
			"budget requires max_calls > 0 and non-negative byte limits", nil)
	}
	return nil
}

// HasReadLimit 는 읽기 바이트 한도가 활성인지 반환한다.
func (b Budget) HasReadLimit() bool { return b.MaxReadBytes > 0 }

// HasWriteLimit 는 쓰기 바이트 한도가 활성인지 반환한다.
func (b Budget) HasWriteLimit() bool { return b.MaxWriteBytes > 0 }

// Within 은 b 가 upper 상한 이내인지 판정한다.
// 상위에 바이트 한도가 있는데 하위가 "한도 없음"이면 무제한 격상이므로 false 다.
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
