package domain

// Epoch 는 주체별 보안 세대 번호다.
// 주체의 권한이 일괄 회수되거나 탈취가 의심될 때 Epoch가 증가하며,
// 증가 전 세대 번호를 보유한 토큰과 상태는 즉시 거부된다.
type Epoch int64

// SecurityEpochs 는 주체(Subject)를 키로 하고 해당 주체의 현재 보안 Epoch를 값으로 갖는 맵이다.
type SecurityEpochs map[string]Epoch

// Get 은 지정된 주체의 현재 Epoch를 반환한다.
// 주체가 등록되지 않았을 경우 기본값 1을 반환한다 (Fail-Closed 및 1-기반 세대 번호 준수).
func (se SecurityEpochs) Get(subject string) Epoch {
	if se == nil {
		return 1
	}
	e, exists := se[subject]
	if !exists || e < 1 {
		return 1
	}
	return e
}

// Bump 는 지정된 주체의 보안 Epoch를 1 증가시키고 새로운 Epoch 값을 반환한다.
func (se SecurityEpochs) Bump(subject string) Epoch {
	current := se.Get(subject)
	next := current + 1
	se[subject] = next
	return next
}
