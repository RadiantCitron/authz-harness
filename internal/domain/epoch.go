// Package domain 은 주체별 보안 세대 번호(Security Epoch) 및 계보 일괄 회수 모델을 정의한다.
//
// [Security Epoch 메커니즘]
// 1. 단일 주체 권한 일괄 즉시 무효화:
//    - 특정 주체(사용자, 워커, 서브에이전트)의 기기가 분실되거나 토큰 탈취가 의심될 때 개별 토큰의 jti 를 하나하나 폐기하는 대신,
//      해당 주체의 Epoch 를 1 증가(Bump)시킨다.
// 2. 시간 불일치 없는 즉각적 무효화:
//    - PDP 인가 판정 및 토큰 검증 시, 토큰에 각인된 epoch 와 중앙 상태 저장소의 current_epoch 가 일치하지 않으면
//      ReasonSubjectEpochRevoked 로 즉시 거부된다.
// 3. RFC 8693 위임 계보 연쇄 회수 (Cascading Revocation):
//    - 자식 토큰의 ActorClaim 계보에 기록된 선대 조상의 Epoch 중 어느 하나라도 현재 활성 Epoch 보다 낮으면
//      위임 고리 전체가 파기된 것으로 간주되어 자식 토큰도 함께 무효화된다.
package domain

// Epoch 는 주체별 보안 세대 번호(Security Generation Number)다.
// 1-기반의 양의 정수(1, 2, 3...)로 관리된다.
type Epoch int64

// SecurityEpochs 는 주체(Subject)를 키로 하고 해당 주체의 현재 보안 Epoch 를 값으로 갖는 맵이다.
// 동시성 안전성을 위해 복사본을 반환하거나 호출자 스냅샷 격리 형태로 다뤄진다.
type SecurityEpochs map[string]Epoch

// Get 은 지정된 주체의 현재 Epoch 를 반환한다.
// 주체가 등록되지 않았거나 값이 1 미만일 경우 기본값 1을 반환한다 (1-기반 세대 번호 및 Fail-Closed 준수).
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

// Bump 는 지정된 주체의 보안 Epoch 를 1 증가시키고 새로 갱신된 Epoch 값을 반환한다.
// 이 작업으로 인해 해당 주체가 이전에 발급받은 모든 기존 토큰과 하위 위임 토큰이 일괄 무효화된다.
func (se SecurityEpochs) Bump(subject string) Epoch {
	current := se.Get(subject)
	next := current + 1
	se[subject] = next
	return next
}
