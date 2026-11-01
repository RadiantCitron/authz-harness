package ui

import (
	"fmt"
	"io"
	"strings"
	"time"

	"authz-harness/internal/harness"
)

// Format 은 SummaryFormatter 의 Formatter 인터페이스 구현체다.
func (f *SummaryFormatter) Format(results []harness.ScenarioResult) error {
	summaryText := RenderSummaryTable(results)
	_, err := io.WriteString(f.out, summaryText)
	return err
}

// RenderSummaryTable 은 전체 시나리오 실행 결과를 ASCII 테이블로 렌더링한다.
func RenderSummaryTable(results []harness.ScenarioResult) string {
	var sb strings.Builder

	sb.WriteString("========================================================================================================================\n")
	sb.WriteString(" authz-harness v0.1.0 — 7대 그룹 30개 E2E 시나리오 실행 결과 요약표\n")
	sb.WriteString("========================================================================================================================\n")
	sb.WriteString(" ID     GROUP  시나리오 명칭                               기대코드 실제코드 [Exit/File/Audit/Hash] 결과   소요시간\n")
	sb.WriteString("------------------------------------------------------------------------------------------------------------------------\n")

	total := len(results)
	passedCount := 0
	var totalDuration time.Duration

	for _, res := range results {
		meta := res.Metadata
		assertion := res.Assertion
		totalDuration += res.Duration

		if res.Passed {
			passedCount++
		}

		exitCheck := "V"
		if !assertion.ExitCodePassed {
			exitCheck = "X"
		}
		fileCheck := "V"
		if !assertion.FilePassed {
			fileCheck = "X"
		}
		auditCheck := "V"
		if !assertion.AuditPassed {
			auditCheck = "X"
		}
		hashCheck := "V"
		if !assertion.HashChainPassed {
			hashCheck = "X"
		}

		quadChecks := fmt.Sprintf("[%2s /%2s /%2s /%2s ]", exitCheck, fileCheck, auditCheck, hashCheck)

		verdict := "PASS"
		if !res.Passed {
			verdict = "FAIL"
		}

		// 한글 폭 고려하여 이름 자르거나 패딩
		displayName := truncateOrPad(meta.Name, 42)

		sb.WriteString(fmt.Sprintf(" %-6s %-6s %-42s %-8d %-8d %-22s %-6s %8.1fms\n",
			meta.ID,
			meta.Group,
			displayName,
			meta.Expected.ExitCode,
			assertion.ExitCodeActual,
			quadChecks,
			verdict,
			float64(res.Duration.Microseconds())/1000.0,
		))
	}

	sb.WriteString("------------------------------------------------------------------------------------------------------------------------\n")
	failedCount := total - passedCount
	sb.WriteString(fmt.Sprintf(" [종합 결산] 총 시나리오: %d건 | 통과(PASS): %d건 | 실패(FAIL): %d건 | 총 소요시간: %.1fms\n",
		total, passedCount, failedCount, float64(totalDuration.Microseconds())/1000.0))

	if failedCount == 0 {
		sb.WriteString(" >> 최종 판정: ALL SCENARIOS PASSED (보안 불변식 100% 사수 증명 완료)\n")
	} else {
		sb.WriteString(fmt.Sprintf(" >> 최종 판정: %d SCENARIO(S) FAILED (보안 결함 발견)\n", failedCount))
	}
	sb.WriteString("========================================================================================================================\n")

	return sb.String()
}

func truncateOrPad(s string, targetLen int) string {
	// 룬 단위 길이 계산
	runes := []rune(s)
	// 대략적인 터미널 표시 너비: 한글 등 와이드 문자 2칸, 영문/기호 1칸
	width := 0
	for _, r := range runes {
		if r > 127 {
			width += 2
		} else {
			width += 1
		}
	}

	if width > targetLen {
		// 자르기
		curW := 0
		var cut []rune
		for _, r := range runes {
			rw := 1
			if r > 127 {
				rw = 2
			}
			if curW+rw > targetLen-2 {
				break
			}
			curW += rw
			cut = append(cut, r)
		}
		cut = append(cut, '.', '.')
		curW += 2
		for curW < targetLen {
			cut = append(cut, ' ')
			curW++
		}
		return string(cut)
	}

	pad := targetLen - width
	return s + strings.Repeat(" ", pad)
}
