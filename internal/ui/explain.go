package ui

import (
	"fmt"
	"io"
	"strings"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

// Format 은 ExplainFormatter 의 Formatter 인터페이스 구현체다.
func (f *ExplainFormatter) Format(results []harness.ScenarioResult) error {
	for _, res := range results {
		view := RenderScenarioExplain(res)
		if _, err := io.WriteString(f.out, view); err != nil {
			return err
		}
	}
	return nil
}

// RenderScenarioExplain 은 단일 시나리오의 초보자용 Explain UX 뷰를 렌더링한다.
func RenderScenarioExplain(res harness.ScenarioResult) string {
	var sb strings.Builder
	meta := res.Metadata
	assertion := res.Assertion

	verdictStr := "PASS (보안 방어 성공)"
	if !res.Passed {
		verdictStr = "FAIL (검증 실패)"
	}

	quadSummary := fmt.Sprintf("[종료코드: %d(기대 %d)] [파일상태: %s] [감사사유: %s] [해시체인: %v]",
		assertion.ExitCodeActual, meta.Expected.ExitCode,
		summarizeFileStatus(assertion),
		assertion.AuditActualReason,
		assertion.HashChainPassed,
	)

	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf(" 시나리오 [%s]: %s\n", meta.ID, meta.Name))
	sb.WriteString("================================================================================\n")
	sb.WriteString(" [기본 정보]\n")
	sb.WriteString(fmt.Sprintf("  - 그룹: %s (%s)\n", meta.Group, meta.Description))
	sb.WriteString(fmt.Sprintf("  - 판정 결과: %s [소요시간: %v]\n", verdictStr, res.Duration))
	sb.WriteString(fmt.Sprintf("  - Quad-Assertion: %s\n", quadSummary))
	if len(assertion.FailureReasons) > 0 {
		sb.WriteString("  - 실패 사유:\n")
		for _, f := range assertion.FailureReasons {
			sb.WriteString(fmt.Sprintf("    * %s\n", f))
		}
	}
	sb.WriteString("\n [관문 상태 파이프라인]\n")

	gates := ComputePipelineGates(res)
	sb.WriteString(RenderPipelineDiagram(gates))
	sb.WriteString(RenderSupervisionLine(ComputeSupervision(res)))

	sb.WriteString("\n [💡 초보자를 위한 보안 원리 해설 (부정 테스트의 역설)]\n")
	explanation := generateExplanation(res, gates)
	sb.WriteString(explanation)
	sb.WriteString("================================================================================\n\n")

	return sb.String()
}

func summarizeFileStatus(assertion harness.AssertionResult) string {
	if assertion.FilePassed {
		return "무결성 유지"
	}
	return "부작용 검출"
}

func generateExplanation(res harness.ScenarioResult, gates []GateInfo) string {
	meta := res.Metadata
	actualExit := res.Assertion.ExitCodeActual
	expectedExit := meta.Expected.ExitCode

	var sb strings.Builder

	if expectedExit == domain.ExitSuccess {
		sb.WriteString("  - 질문: 왜 이 작업은 정상 종료(Exit Code 0)되어야 하나요?\n")
		sb.WriteString("  - 해설: 올바른 권한과 유효한 서명 토큰을 제시하고 격리된 디렉터리 내에서\n")
		sb.WriteString("          수행된 합법적인 요청입니다. 6대 관문을 모두 통과하여 I/O가 정상 수행되었습니다.\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("  - 질문: 왜 프로세스는 실패(Exit Code %d)했는데 하네스는 PASS(통과)라고 하나요?\n", actualExit))

	// 차단 관문 찾기
	var blockedGate *GateInfo
	for i := range gates {
		if gates[i].Status == GateBlocked {
			blockedGate = &gates[i]
			break
		}
	}

	gateName := "관문"
	if blockedGate != nil {
		gateName = blockedGate.Name
	}

	switch meta.Group {
	case "G1":
		sb.WriteString(fmt.Sprintf("  - 해설: 권한이 회수되었거나 존재하지 않는 상태에서의 비인가 요청입니다.\n          %s에서 정확히 이 요청을 거부하고 I/O 부작용 없이 종료 코드 %d를 반환했으므로\n          보안 관점에서 완벽히 방어에 '성공'한 것입니다.\n", gateName, actualExit))
	case "G2":
		sb.WriteString(fmt.Sprintf("  - 해설: 변조된 토큰이나 잘못된 서명을 가진 비인가 요청입니다.\n          %s에서 위조를 즉시 감지하여 차단하고 안전하게 종료 코드 %d를 반환했으므로\n          보안 관점에서 공격 방어에 '성공'한 것입니다.\n", gateName, actualExit))
	case "G3":
		sb.WriteString(fmt.Sprintf("  - 해설: 만료되었거나 미래의 유효 시간을 가진 비정상 토큰입니다.\n          %s에서 시간 불변식 위반을 포착하여 0바이트 상태로 차단했으므로\n          보안 시스템이 신뢰를 성공적으로 사수한 것입니다.\n", gateName))
	case "G4":
		sb.WriteString(fmt.Sprintf("  - 해설: 폐기된 키 또는 이미 사용된 토큰(Replay)으로 접근을 시도했습니다.\n          %s에서 무효화된 상태를 실시간 확인하여 차단에 성공했습니다.\n", gateName))
	case "G5":
		sb.WriteString(fmt.Sprintf("  - 해설: 위임 범위를 벗어난 권한 초과(Privilege Escalation) 공격입니다.\n          부모 토큰보다 큰 권한을 자식이 행사하려 했으나 %s에서 이를 적발하여\n          종료 코드 %d로 방어했습니다.\n", gateName, actualExit))
	case "G6":
		sb.WriteString(fmt.Sprintf("  - 해설: 작업 디렉터리(Workspace Jail) 바깥의 민감한 파일에 접근하려는 탈출 시도입니다.\n          상대경로나 심볼릭 링크 공격을 %s에서 차단하여 호스트를 안전하게 격리했습니다.\n", gateName))
	case "G7":
		sb.WriteString("  - 해설: 감사 기록 실패 시 기본 거부(Fail-Closed) 및 사후 위변조 탐지 원칙을 증명합니다.\n          보안 감사 추적이 불가능한 상태에서 작업을 강행하지 않고 안전하게 정지했습니다.\n")
	case "G9":
		sb.WriteString("  - 해설: 판정(허용/거부)과 별개로, 부모가 시간·출력 한계를 넘은 워커와 그 자식 전체를 끝냈다.\n")
	case "G11":
		if meta.Expected.ExitCode == domain.ExitSuccess {
			sb.WriteString("  - 해설: 예산이 나뉘어 위임되고 회수되어도 합계가 보존됨을 원장 잔량으로 확인했다.\n          자식 예산은 부모 잔여를 넘지 못하며(DELEGATION_BUDGET_EXCEEDED), 소비는 토큰이 아니라 Zone B 예산 원장에서 원자적으로 차감된다.\n")
		} else {
			sb.WriteString(fmt.Sprintf("  - 해설: 예산 한도를 넘는 위임 또는 호출이 %s에서 거부되었다(종료 코드 %d).\n          예산 소진(BUDGET_EXHAUSTED)과 위임 초과(DELEGATION_BUDGET_EXCEEDED)는 모두 인가 거부(12)이며, 파일은 한 바이트도 바뀌지 않았다.\n", gateName, actualExit))
		}
	case "G12":
		if meta.Expected.ExitCode == domain.ExitSuccess {
			sb.WriteString("  - 해설: 만료된 자식 토큰은 거부됐지만, 유효한 부모 토큰으로 새 자식을 재교환해 같은 세션이 작업을 이어갔다.\n          Refresh Token 없이도 자식 수명은 부모 수명 안에 묶인다.\n")
		} else {
			sb.WriteString(fmt.Sprintf("  - 해설: 같은 세션 안에서 시간 경과·계보 회수·키 폐기·재사용·재교환 같은 상태 변화 뒤의 호출이 %s에서 거부되었다(종료 코드 %d).\n          세션이 열려 있어도 판정은 호출마다 최신 상태로 다시 이뤄진다.\n", gateName, actualExit))
		}
	case "G13":
		if meta.Expected.ExitCode == domain.ExitSuccess {
			sb.WriteString("  - 해설: 감사는 인자·결과의 SHA-256 지문만 남기고 원문은 남기지 않았다. 관측성 포트가 고장나도 판정과 감사는 그대로였고,\n          v1 레코드 뒤에 v2 레코드가 이어져도 한 체인으로 검증된다.\n")
		} else {
			sb.WriteString(fmt.Sprintf("  - 해설: 해시 체인만으로는 못 잡는 꼬리 절단·전체 재작성·검증 재료 부재를 서명 체크포인트가 %s에서 적발했다(종료 코드 %d).\n          체인 자체는 유효해도 체크포인트와 어긋나면 통과가 아니라 거부(Fail-Closed)다.\n", gateName, actualExit))
		}
	case "G10":
		if meta.Expected.Audit.ExpectedReason == domain.ReasonConfinementUnavailable {
			sb.WriteString("  - 해설: 격리 필수 모드인데 OS 격리(CONFINEMENT_UNAVAILABLE)를 적용할 수 없어 부모가 자식을 기동하지 않고 거부(Fail-Closed, 16)했다.\n")
		} else {
			sb.WriteString("  - 해설: PEP 를 건너뛰는 악의 워커를 격리 끔(대조군: 공격 성공)과 켬(실험군: 차단)으로 쌍 대조했다.\n          차단은 앱 코드가 아니라 OS 커널이 한 것이며, 판정은 부모가 관찰한 사실(canary·파일·리스너)로만 내렸다.\n")
		}
	default:
		sb.WriteString(fmt.Sprintf("  - 해설: 비인가 공격이 %s에서 탐지되어 시스템이 안전하게 거부(Fail-Closed)되었습니다.\n", gateName))
	}

	return sb.String()
}
