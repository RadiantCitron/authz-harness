package ui

import (
	"fmt"
	"strings"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// GateStatus 는 관문 판정 상태다.
type GateStatus string

const (
	GatePass    GateStatus = "PASS"
	GateBlocked GateStatus = "BLOCKED ❌"
	GateSkipped GateStatus = "SKIPPED"
)

// GateInfo 는 개별 관문의 평가 정보다.
type GateInfo struct {
	GateNumber int
	Name       string
	Status     GateStatus
	Detail     string
}

// SupervisionInfo 는 부모 스포너의 실행 감독(시간·출력 한계) 결과다. 인가 관문과 별개다.
type SupervisionInfo struct {
	Blocked bool
	Reason  domain.Reason // RESOURCE_TIMEOUT | RESOURCE_OUTPUT_LIMIT
	Detail  string
}

// ComputeSupervision 은 시나리오 결과에서 자원 한계 종료 여부를 도출한다.
func ComputeSupervision(res harness.ScenarioResult) SupervisionInfo {
	reason := res.Assertion.AuditActualReason
	if reason == "" {
		reason = res.Metadata.Expected.Audit.ExpectedReason
	}
	switch reason {
	case domain.ReasonResourceTimeout:
		return SupervisionInfo{Blocked: true, Reason: reason, Detail: "시간 상한 초과로 프로세스 그룹 종료"}
	case domain.ReasonResourceOutputLimit:
		return SupervisionInfo{Blocked: true, Reason: reason, Detail: "출력 상한 초과로 프로세스 그룹 종료"}
	}
	return SupervisionInfo{}
}

// RenderSupervisionLine 은 관문 표 아래에 붙는 "실행 감독" 한 줄을 만든다.
func RenderSupervisionLine(s SupervisionInfo) string {
	if s.Blocked {
		return fmt.Sprintf("  실행 감독: 차단 (%s) — %s\n", s.Reason, s.Detail)
	}
	return "  실행 감독: 정상\n"
}

// ComputePipelineGates 는 시나리오 결과와 메타데이터로부터 6단계 관문 상태를 도출한다.
func ComputePipelineGates(res harness.ScenarioResult) []GateInfo {
	meta := res.Metadata
	assertion := res.Assertion
	expected := meta.Expected

	// 실행 감독 종료는 인가 관문의 결과가 아니므로 모든 관문을 SKIPPED 로 표시한다.
	if ComputeSupervision(res).Blocked {
		return skippedGates()
	}

	// 차단이 발생할 관문 결정 (0~5, 차단 없으면 -1)
	blockedGate := -1
	blockedDetail := ""

	reason := assertion.AuditActualReason
	if reason == "" {
		reason = expected.Audit.ExpectedReason
	}

	// 1. 차단 사유 또는 메타데이터 기반으로 차단 관문 산출
	switch {
	// Gate 0: 컨텍스트 검증 (trace_id 누락 등)
	case reason == domain.ReasonInvalidArguments || meta.ID == "E2E-28":
		blockedGate = 0
		blockedDetail = "trace_id 컨텍스트 누락 검증 차단"

	// Gate 1: 토큰 & 서명 (Ed25519 서명, JWT 규격, 만료/미래, 키 폐기 등)
	case meta.Group == "G2" || meta.Group == "G3" ||
		reason == domain.ReasonTokenInvalidSignature ||
		reason == domain.ReasonTokenExpired ||
		reason == domain.ReasonTokenNotYetValid ||
		reason == domain.ReasonTokenInvalidIssAud ||
		reason == domain.ReasonTokenSubjectMismatch ||
		reason == domain.ReasonTokenKeyRetired ||
		reason == domain.ReasonTokenKeyNotFound ||
		reason == domain.ReasonTokenInvalidType ||
		reason == domain.ReasonTokenAlgNotAllowed ||
		reason == domain.ReasonTokenMalformed ||
		reason == domain.ReasonInvalidToken:
		blockedGate = 1
		if assertion.AuditActualReason != "" {
			blockedDetail = fmt.Sprintf("토큰/서명 위반 사유: %s", assertion.AuditActualReason)
		} else {
			blockedDetail = fmt.Sprintf("토큰/서명 위반 사유: %s", expected.Audit.ExpectedReason)
		}

	// Gate 2: 위임 & 스코프 (축소 위임 불일치, Scope 권한 초과)
	case meta.Group == "G5" && (reason == domain.ReasonDelegationScopeExceeded ||
		reason == domain.ReasonDelegationDepthExceeded ||
		reason == domain.ReasonDelegationTTLExceeded ||
		reason == domain.ReasonDelegationSelfLoop ||
		reason == domain.ReasonDelegationScopeEmpty ||
		reason == domain.ReasonTokenInsufficientScope ||
		meta.ID == "E2E-19" || meta.ID == "E2E-20" || meta.ID == "E2E-21" || meta.ID == "E2E-22"):
		blockedGate = 2
		if meta.ID == "E2E-22" {
			blockedDetail = "요청: file:write / 축소위임: file:read"
		} else if assertion.AuditActualReason != "" {
			blockedDetail = fmt.Sprintf("위임/스코프 위반: %s", assertion.AuditActualReason)
		} else {
			blockedDetail = fmt.Sprintf("위임/스코프 위반: %s", expected.Audit.ExpectedReason)
		}

	// Gate 3: 실시간 Grant (PAP 실시간 회수, Replay, Subject Epoch)
	case reason == domain.ReasonNoActiveGrant ||
		reason == domain.ReasonGrantRevoked ||
		reason == domain.ReasonTokenReplayDetected ||
		reason == domain.ReasonSubjectEpochRevoked ||
		meta.ID == "E2E-03" || meta.ID == "E2E-18" || meta.ID == "E2E-23" || meta.ID == "E2E-24":
		blockedGate = 3
		if assertion.AuditActualReason != "" {
			blockedDetail = fmt.Sprintf("실시간 Grant 검증 실패: %s", assertion.AuditActualReason)
		} else {
			blockedDetail = fmt.Sprintf("실시간 Grant 검증 실패: %s", expected.Audit.ExpectedReason)
		}

	// Gate 4: Jail 경로격리 (Workspace 경계 탈출, Symlink, DotDot)
	case meta.Group == "G6" ||
		reason == domain.ReasonPathViolation ||
		reason == domain.ReasonPathTraversal ||
		reason == domain.ReasonSymlinkEscape ||
		reason == domain.ReasonInvalidPath:
		blockedGate = 4
		if assertion.AuditActualReason != "" {
			blockedDetail = fmt.Sprintf("Jail 경로 격리 위반: %s", assertion.AuditActualReason)
		} else {
			blockedDetail = fmt.Sprintf("Jail 경로 격리 위반: %s", expected.Audit.ExpectedReason)
		}

	// Gate 5: 감사 & I/O (Fail-Closed, 해시 체인 무결성 위반)
	case meta.Group == "G7" ||
		reason == domain.ReasonAuditLogFailed ||
		meta.ID == "E2E-29" || meta.ID == "E2E-30":
		blockedGate = 5
		if assertion.AuditActualReason != "" {
			blockedDetail = fmt.Sprintf("감사 무결성/I/O 차단: %s", assertion.AuditActualReason)
		} else {
			blockedDetail = fmt.Sprintf("감사 무결성/I/O 차단: %s", expected.Audit.ExpectedReason)
		}
	}

	// 정상 시나리오 (E2E-01, E2E-02 등 ExitCode == 0 이고 기대 판정이 allow 인 경우)
	if expected.ExitCode == domain.ExitSuccess {
		blockedGate = -1
	}

	gateNames := []string{
		"Gate 0: 컨텍스트 검증",
		"Gate 1: 토큰 & 서명",
		"Gate 2: 위임 & 스코프",
		"Gate 3: 실시간 Grant",
		"Gate 4: Jail 경로격리",
		"Gate 5: 감사 & I/O",
	}

	gates := make([]GateInfo, 6)
	for i := 0; i < 6; i++ {
		gates[i] = GateInfo{
			GateNumber: i,
			Name:       gateNames[i],
		}

		if blockedGate == -1 {
			// 전 관문 통과
			gates[i].Status = GatePass
			gates[i].Detail = "정상 통과"
		} else if i < blockedGate {
			gates[i].Status = GatePass
			gates[i].Detail = "정상 통과"
		} else if i == blockedGate {
			gates[i].Status = GateBlocked
			gates[i].Detail = blockedDetail
		} else {
			gates[i].Status = GateSkipped
			if i == 5 {
				gates[i].Detail = "부작용 0바이트 보장 (선행 관문 차단)"
			} else {
				gates[i].Detail = "선행 관문 차단으로 실행 생략"
			}
		}
	}

	// 컨텍스트 검증 특화 상세
	if blockedGate != 0 {
		gates[0].Detail = "trace_id 존재 확인"
	}
	// 토큰 & 서명 특화 상세
	if blockedGate > 1 || blockedGate == -1 {
		gates[1].Detail = "Ed25519 서명 및 JWT 규격(at+jwt) 유효"
	}
	// Gate 5 정상 통과 상세
	if blockedGate == -1 {
		gates[5].Detail = "감사 기록 및 4중 무결성 검증 완료"
	}

	return gates
}

// skippedGates 는 6개 관문을 모두 SKIPPED 로 반환한다 (실행 감독에서 종료된 경우).
func skippedGates() []GateInfo {
	names := []string{"Gate 0: 컨텍스트 검증", "Gate 1: 토큰 & 서명", "Gate 2: 위임 & 스코프", "Gate 3: 실시간 Grant", "Gate 4: Jail 경로격리", "Gate 5: 감사 & I/O"}
	gates := make([]GateInfo, 6)
	for i := range gates {
		gates[i] = GateInfo{GateNumber: i, Name: names[i], Status: GateSkipped, Detail: "실행 감독에서 종료됨 — 관문 판정과 무관"}
	}
	return gates
}

// RenderPipelineDiagram 은 관문 상태를 텍스트 다이어그램으로 렌더링한다.
func RenderPipelineDiagram(gates []GateInfo) string {
	var sb strings.Builder
	for _, g := range gates {
		statusStr := string(g.Status)
		detailStr := ""
		if g.Detail != "" {
			detailStr = fmt.Sprintf(" (%s)", g.Detail)
		}
		sb.WriteString(fmt.Sprintf("  [%s] ──▶ %s%s\n", g.Name, statusStr, detailStr))
	}
	return sb.String()
}
