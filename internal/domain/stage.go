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
