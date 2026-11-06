package ui

import (
	"fmt"
	"strings"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// CellState 는 단계 칸의 표시 상태다.
type CellState string

const (
	CellPassed   CellState = "통과"
	CellBlocked  CellState = "차단"
	CellSkipped  CellState = "건너뜀"   // 앞 단계가 막아서 돌지 않음
	CellNA       CellState = "해당 없음" // 조건에 맞지 않아 돌지 않음
	CellNotEnter CellState = "미진입"   // 요청이 PEP 에 닿지 않음
	CellUnknown  CellState = "판단 불가" // 기록에 근거가 없음
)

// StageCell 은 화면의 칸 하나다. 칸 목록과 이름은 domain.PEPStages() 에서 읽는다.
type StageCell struct {
	Stage  domain.Stage
	Label  string
	State  CellState
	Detail string
}

// StageView 는 한 시나리오의 화면 모델이다. 관문 밖 판정은 칸이 아니라 Side 줄로 둔다.
type StageView struct {
	Cells []StageCell
	Side  []string
}

// Blocked 는 차단 칸을 돌려준다. 없으면 nil.
func (v StageView) Blocked() *StageCell {
	for i := range v.Cells {
		if v.Cells[i].State == CellBlocked {
			return &v.Cells[i]
		}
	}
	return nil
}

// BuildStageView 는 감사 기록에서 관측한 사실(Assertion.Observed, AuditActualStage)만으로 화면 모델을 만든다.
// 시나리오 ID·그룹·기대값으로 추측하지 않는다. 근거가 없으면 판단 불가로 그린다.
func BuildStageView(res harness.ScenarioResult) StageView {
	a := res.Assertion
	o := a.Observed
	exit := a.ExitCodeActual
	reason := a.AuditActualReason

	all := func(s CellState, detail string) []StageCell {
		specs := domain.PEPStages()
		cells := make([]StageCell, len(specs))
		for i, sp := range specs {
			cells[i] = StageCell{Stage: sp.ID, Label: sp.Label, State: s, Detail: detail}
		}
		return cells
	}

	switch {
	case o.ReadFailed:
		return StageView{Cells: all(CellUnknown, "감사 기록을 읽지 못함")}
	case o.Action == "token.issue.deny":
		return StageView{Cells: all(CellNotEnter, ""), Side: []string{fmt.Sprintf("토큰 발급: 차단 (%s)", reason)}}
	case o.Action == "token.exchange.deny":
		return StageView{Cells: all(CellNotEnter, ""), Side: []string{fmt.Sprintf("토큰 교환: 차단 (%s)", reason)}}
	case strings.HasPrefix(o.Action, "agent."):
		side := fmt.Sprintf("실행 감독: 차단 (%s)", reason)
		if o.Action == "agent.confined" {
			side = "격리: 차단"
			if reason != "" {
				side = fmt.Sprintf("격리: 차단 (%s)", reason)
			}
		}
		if o.PEPFound {
			v := pepCells(o.PEPAction, o.PEPStage, o.PEPSchema, exit, o, all)
			v.Side = append(v.Side, side)
			return v
		}
		return StageView{Cells: all(CellNotEnter, ""), Side: []string{side}}
	case o.Action == "pep.allow" || o.Action == "pep.deny":
		return pepCells(o.Action, a.AuditActualStage, o.SchemaVersion, exit, o, all)
	case exit == domain.ExitAuditFailure:
		return StageView{Cells: all(CellUnknown, "단계 기록 없음"), Side: []string{"감사 기록: 실패"}}
	case exit != domain.ExitSuccess:
		return StageView{Cells: all(CellNotEnter, ""), Side: []string{"진입 전: 차단"}}
	default:
		return StageView{Cells: all(CellNotEnter, "")}
	}
}

// pepCells 는 PEP 기록(종단 단계)에서 칸을 그린다. 앞 칸은 감사에 남지 않으므로 근거 있는 규칙으로만 그린다.
func pepCells(action string, stage domain.Stage, schema int, exit domain.ExitCode, o harness.AuditObservation, all func(CellState, string) []StageCell) StageView {
	if schema != 0 && schema < 4 {
		return StageView{Cells: all(CellUnknown, "v3 이하 기록에는 단계가 없음")}
	}
	specs := domain.PEPStages()
	end := -1
	for i, sp := range specs {
		if sp.ID == stage {
			end = i
		}
	}
	if end < 0 {
		return StageView{Cells: all(CellUnknown, "알 수 없는 단계 기록")}
	}
	deny := action == "pep.deny"
	cells := make([]StageCell, len(specs))
	for i, sp := range specs {
		c := StageCell{Stage: sp.ID, Label: sp.Label}
		switch {
		case i == end && deny:
			c.State = CellBlocked
		case i > end && deny:
			c.State = CellSkipped
		case i > end:
			c.State, c.Detail = afterEnd(sp.ID, stage)
		default:
			c.State, c.Detail = beforeEnd(sp.ID, stage, o)
		}
		cells[i] = c
	}
	v := StageView{Cells: cells}
	if !deny && exit == domain.ExitAuditFailure {
		v.Side = append(v.Side, "감사 검증: 차단")
	}
	return v
}

// beforeEnd 는 종단 단계 이하(종단 포함, 허용일 때)의 칸 규칙이다.
func beforeEnd(s, end domain.Stage, o harness.AuditObservation) (CellState, string) {
	switch s {
	case domain.StageApproval:
		if o.ApprovalConsumed {
			return CellPassed, "승인 소비 기록 있음"
		}
		return CellNA, "승인 소비 기록 없음"
	case domain.StageBudget:
		if end == domain.StageSettle {
			return CellPassed, "정산 단계까지 갔으므로 예산 토큰"
		}
		return CellUnknown, "예산 토큰 여부를 알 수 있는 기록이 없음"
	case domain.StageSettle:
		if end == domain.StageSettle {
			return CellPassed, ""
		}
		return CellNA, "정산 없이 완료"
	}
	return CellPassed, ""
}

// afterEnd 는 허용 기록의 종단 단계보다 뒤 칸이다. 완료 감사가 execute 이면 정산은 돌지 않은 것이고,
// 그보다 앞에서 기록이 끝났으면(꼬리 절단 등) 뒤는 근거가 없다.
func afterEnd(s, end domain.Stage) (CellState, string) {
	if s == domain.StageSettle && end == domain.StageExecute {
		return CellNA, "정산 없이 완료"
	}
	return CellUnknown, "완료 기록 없음"
}

// RenderStageView 는 화면 모델을 텍스트로 그린다.
func RenderStageView(v StageView) string {
	var sb strings.Builder
	for _, c := range v.Cells {
		detail := ""
		if c.Detail != "" {
			detail = fmt.Sprintf(" (%s)", c.Detail)
		}
		sb.WriteString(fmt.Sprintf("  [%s] ──▶ %s%s\n", c.Label, c.State, detail))
	}
	for _, s := range v.Side {
		sb.WriteString(fmt.Sprintf("  %s\n", s))
	}
	return sb.String()
}
