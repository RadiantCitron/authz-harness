// Package domain 은 PEP 인가 관문 및 토큰 교환 파이프라인의 공식 단계(Stage) 규약을 정의한다.
//
// [ADR 0007 단계 규약과 설계 원칙]
// 1. 번호 없는 이름 부여:
//    - 단계 이름에 "step1", "step2" 같은 숫자를 넣지 않는다. 파이프라인 단계 순서는 배열의 인덱스로 결정되며,
//      이름 자체는 순수한 기능적·보안적 의미만을 나타낸다.
// 2. 부작용(Side-Effect) 기반 StageKind 분류:
//    - 읽기/판단(check, decide) ➔ 상태 소비(consume) ➔ 영구 기록(record) ➔ 도구 실행(execute) ➔ 사후 정산(settle)
//    - 순서 역전(예: consume 후 check)은 pipeline.Engine 불변식에서 즉시 거부된다.
// 3. 네임스페이스 완전 분리:
//    - PEP 파이프라인 단계(10개)와 토큰 교환소 파이프라인 단계(8개)는 식별자가 절대 중복되지 않는다.
//
// [조립처 크로스체킹 (Cross-Referencing)]
// - PEP 인가 관문 10단계 조립: internal/authz/pep/gateway.go 의 assemble()
// - 토큰 교환소 8단계 조립: internal/authn/exchange/service.go
// - 파이프라인 엔진: internal/pipeline/pipeline.go 의 Step[S] 및 Kind
package domain

// Stage 는 파이프라인 단계를 식별하는 고유 이름이다.
// audit.jsonl 의 stage 필드 및 에러 궤적(Trace.Failed)에 그대로 기록된다.
type Stage string

// StageKind 는 해당 단계가 시스템과 외부 세계에 남기는 부작용(Side Effect)의 수준을 나타내는 성격 등급이다.
// pipeline.Kind 와 1:1 로 대응하며 등급 하강이 불가능한 보안 불변식을 형성한다.
type StageKind string

const (
	// StageInput 은 요청 인자, 액션, 리소스의 유효성과 형식을 사전 검증하는 1단계다 (KindCheck).
	StageInput Stage = "input"

	// StageAuthn 은 Bearer JWT 토큰의 서명, 유효 기간, 발급자, 수신 대상을 검증하는 2단계다 (KindCheck).
	StageAuthn Stage = "authn"

	// StageAuthz 는 PDP 인가 두뇌를 호출하여 활성 권한(Grant) 및 주체 Epoch 를 판정하는 3단계다 (KindDecide).
	StageAuthz Stage = "authz"

	// StageBoundary 는 Jail 샌드박스를 대조하여 파일 경로 순회(../)나 탈출 시도를 차단하는 4단계다 (KindCheck).
	StageBoundary Stage = "boundary"

	// StageReplay 는 토큰의 고유 jti 를 리플레이 장부에 영구 등록하여 재사용 공격을 차단하는 5단계다 (KindConsume).
	StageReplay Stage = "replay"

	// StageApproval 은 ask(수동 승인 필요) 판정된 요청에 대해 일치하는 1회용 승인 티켓을 소비하는 6단계다 (KindConsume).
	StageApproval Stage = "approval"

	// StageBudget 은 토큰에 할당된 호출 횟수 및 I/O 바이트 예산을 장부에서 사전 차감하는 7단계다 (KindConsume).
	// 후속 단계(감사 기록 등) 실패 시 LIFO 역순 보상(Compensate/Refund)으로 즉시 환불된다.
	StageBudget Stage = "budget"

	// StagePrecommitAudit 는 실제 도구 실행 직전, 모든 인가 판정 및 컨텍스트를 audit.jsonl 해시 체인에 기록하는 8단계다 (KindRecord).
	StagePrecommitAudit Stage = "precommit_audit"

	// StageExecute 는 파일 읽기/쓰기, 네트워크 송신, 커맨드 실행 등 실제 도구를 샌드박스 내에서 집행하는 9단계다 (KindExecute).
	StageExecute Stage = "execute"

	// StageSettle 은 실행 후 실제 소비된 I/O 바이트를 반영하여 사전 차감분을 정산하고 결과를 래핑하는 10단계다 (KindSettle).
	StageSettle Stage = "settle"
)

// 토큰 교환소(Token Exchange / RFC 8693) 8단계 파이프라인 규약이다.
// PEP 검문소 단계와 이름이 겹치지 않도록 완전히 분리되어 있다.
const (
	// StageClientAuth 는 교환 요청을 보낸 클라이언트(OAuth 2.1 client_id/secret)를 인증하는 1단계다 (KindCheck).
	StageClientAuth Stage = "client_auth"

	// StageDelegationSubject 는 위임 대상 주체(sub)와 요청자가 올바른지 검증하는 2단계다 (KindCheck).
	StageDelegationSubject Stage = "delegation_subject"

	// StageParentToken 은 위임의 근거가 되는 부모 Bearer 토큰의 서명과 유효성을 검증하는 3단계다 (KindCheck).
	StageParentToken Stage = "parent_token"

	// StageLineageEpoch 는 부모 및 선대 조상(act) 위임 계보 전체의 Security Epoch 가 유효한지 대조하는 4단계다 (KindCheck).
	StageLineageEpoch Stage = "lineage_epoch"

	// StageDownscope 는 자식 토큰의 요청 스코프와 수명(exp)이 부모의 진부분집합(Strict Subset)인지 판정하는 5단계다 (KindDecide).
	StageDownscope Stage = "downscope"

	// StageBudgetDownscope 는 자식 토큰에 분할해 줄 예산이 부모 잔여 예산 이내인지 검증하는 6단계다 (KindCheck).
	StageBudgetDownscope Stage = "budget_downscope"

	// StageTokenIssue 는 검증된 하위 권한과 위임 계보(act)를 담아 자식 JWT 를 비대칭키로 신규 발급하는 7단계다 (KindExecute).
	StageTokenIssue Stage = "token_issue"

	// StageBudgetReserve 는 부모 예산 장부에서 자식에게 분할된 예산을 차감 예약하는 8단계다 (KindSettle).
	StageBudgetReserve Stage = "budget_reserve"
)

const (
	// KindCheck 는 상태를 변경하지 않는 읽기 전용 검증 성격이다 (순위 0).
	KindCheck StageKind = "check"

	// KindDecide 는 정책에 따라 허용/거부/승인필요를 결정하는 인가 판단 성격이다 (순위 0).
	KindDecide StageKind = "decide"

	// KindConsume 은 예산, 승인 티켓, jti 등 소비 가능한 자원을 소모하는 성격이다 (순위 1).
	KindConsume StageKind = "consume"

	// KindRecord 는 감사 로그 등 영구 불변 증거를 디스크에 기록하는 성격이다 (순위 2).
	KindRecord StageKind = "record"

	// KindExecute 는 실제 도구 또는 OS 프로세스를 실행하는 성격이다 (순위 3).
	KindExecute StageKind = "execute"

	// KindSettle 은 잔여 예산 환불 및 결과 정산 사후 처리 성격이다 (순위 4).
	KindSettle StageKind = "settle"
)

// StageSpec 은 파이프라인을 이루는 단일 단계의 메타데이터 정의 명세다.
type StageSpec struct {
	// ID 는 단계의 고유 식별자다.
	ID Stage

	// Kind 는 단계의 부작용 성격 등급이다.
	Kind StageKind

	// Conditional 이 true 면 모든 요청에 필수 실행되지 않고 특정 조건(예: 승인 필요, 예산 포함)에 따라 건너뛸 수 있음을 의미한다.
	Conditional bool

	// Label 은 CLI UI 및 설명서 화면에 표시할 공식 한국어 명칭이다.
	Label string
}

// pepStages 는 PEP 인가 관문 10단계의 공식 순서 불변 명세다.
var pepStages = []StageSpec{
	{StageInput, KindCheck, false, "입력 검사"},
	{StageAuthn, KindCheck, false, "신원 확인"},
	{StageAuthz, KindDecide, false, "권한 판정"},
	{StageBoundary, KindCheck, false, "경계 검사"},
	{StageReplay, KindConsume, false, "재사용 방지"},
	{StageApproval, KindConsume, true, "승인 소비"},
	{StageBudget, KindConsume, true, "예산 차감"},
	{StagePrecommitAudit, KindRecord, false, "실행 전 감사 기록"},
	{StageExecute, KindExecute, false, "실행"},
	{StageSettle, KindSettle, true, "사후 정산"},
}

// PEPStages 는 PEP 단계의 정식 순서 목록의 복사본을 반환한다.
//
// [Go 관용구: 방어적 복사 (Defensive Copy)]
// 내부 슬라이스 pepStages 를 직접 반환하면 외부 호출자가 요소를 수정하여 전역 상태가 오염될 수 있으므로,
// make 와 copy 를 통해 독립된 새 슬라이스 복사본을 할당하여 불변성을 보장한다.
func PEPStages() []StageSpec {
	out := make([]StageSpec, len(pepStages))
	copy(out, pepStages)
	return out
}

// exchangeStages 는 토큰 축소 위임 교환소 8단계의 공식 순서 불변 명세다.
var exchangeStages = []StageSpec{
	{StageClientAuth, KindCheck, false, "클라이언트 인증"},
	{StageDelegationSubject, KindCheck, false, "위임 대상 확인"},
	{StageParentToken, KindCheck, false, "부모 토큰 검증"},
	{StageLineageEpoch, KindCheck, true, "계보 Epoch 대조"},
	{StageDownscope, KindDecide, false, "축소 위임 판정"},
	{StageBudgetDownscope, KindCheck, true, "예산 축소 검사"},
	{StageTokenIssue, KindExecute, false, "자식 토큰 발급"},
	{StageBudgetReserve, KindSettle, true, "예산 예약"},
}

// ExchangeStages 는 토큰 교환 단계의 정식 순서 목록의 복사본을 반환한다 (방어적 복사).
func ExchangeStages() []StageSpec {
	out := make([]StageSpec, len(exchangeStages))
	copy(out, exchangeStages)
	return out
}
