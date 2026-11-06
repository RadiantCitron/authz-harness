package domain

// Stage 는 PEP 파이프라인 단계의 이름이다. 이름에 번호를 넣지 않는다(ADR 0007 2장 4번).
type Stage string

// StageKind 는 단계가 세상에 남기는 부작용으로 나눈 성격이다(ADR 0007 2장 1~2번).
type StageKind string

const (
	StageInput          Stage = "input"
	StageAuthn          Stage = "authn"
	StageAuthz          Stage = "authz"
	StageBoundary       Stage = "boundary"
	StageReplay         Stage = "replay"
	StageApproval       Stage = "approval"
	StageBudget         Stage = "budget"
	StagePrecommitAudit Stage = "precommit_audit"
	StageExecute        Stage = "execute"
	StageSettle         Stage = "settle"
)

// 토큰 교환 단계다. PEP 단계와 이름이 겹치지 않는다.
const (
	StageClientAuth        Stage = "client_auth"
	StageDelegationSubject Stage = "delegation_subject"
	StageParentToken       Stage = "parent_token"
	StageLineageEpoch      Stage = "lineage_epoch"
	StageDownscope         Stage = "downscope"
	StageBudgetDownscope   Stage = "budget_downscope"
	StageTokenIssue        Stage = "token_issue"
	StageBudgetReserve     Stage = "budget_reserve"
)

const (
	KindCheck   StageKind = "check"
	KindDecide  StageKind = "decide"
	KindConsume StageKind = "consume"
	KindRecord  StageKind = "record"
	KindExecute StageKind = "execute"
	KindSettle  StageKind = "settle"
)

// StageSpec 은 단계 하나의 정의다. Label 은 화면용 한국어 이름이다.
type StageSpec struct {
	ID          Stage
	Kind        StageKind
	Conditional bool
	Label       string
}

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

// PEPStages 는 PEP 단계의 정식 순서 목록의 복사본을 돌려준다.
func PEPStages() []StageSpec {
	out := make([]StageSpec, len(pepStages))
	copy(out, pepStages)
	return out
}

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

// ExchangeStages 는 토큰 교환 단계의 정식 순서 목록의 복사본을 돌려준다.
func ExchangeStages() []StageSpec {
	out := make([]StageSpec, len(exchangeStages))
	copy(out, exchangeStages)
	return out
}
