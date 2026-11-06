package ui

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
)

func sampleResult(id, group, name string, expectedExit, actualExit domain.ExitCode, passed bool) harness.ScenarioResult {
	return harness.ScenarioResult{
		Metadata: harness.ScenarioMetadata{
			ID:          id,
			Group:       group,
			Name:        name,
			Description: "테스트 설명",
			Expected: harness.ExpectedAssertion{
				ExitCode: expectedExit,
				Audit: harness.AuditExpectation{
					ExpectedReason: domain.ReasonTokenInsufficientScope,
				},
			},
		},
		Passed:   passed,
		Duration: 2 * time.Millisecond,
		Assertion: harness.AssertionResult{
			Passed:              passed,
			ExitCodePassed:      expectedExit == actualExit,
			ExitCodeActual:      actualExit,
			FilePassed:          true,
			AuditPassed:         true,
			AuditActualReason:   domain.ReasonTokenInsufficientScope,
			AuditActualDecision: "deny",
			AuditActualStage:    domain.StageAuthz,
			Observed:            harness.AuditObservation{Action: "pep.deny", SchemaVersion: 4},
			HashChainPassed:     true,
		},
	}
}

func TestSummaryFormatter(t *testing.T) {
	results := []harness.ScenarioResult{
		sampleResult("E2E-01", "G1", "정상 단일 파일 읽기", domain.ExitSuccess, domain.ExitSuccess, true),
		sampleResult("E2E-22", "G5", "축소 위임 토큰 쓰기 거부", domain.ExitAuthzDenied, domain.ExitAuthzDenied, true),
	}

	var buf bytes.Buffer
	formatter := NewSummaryFormatter(&buf)
	err := formatter.Format(results)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "E2E-01") || !strings.Contains(out, "E2E-22") {
		t.Errorf("expected IDs in summary output, got: %s", out)
	}
	if !strings.Contains(out, "ALL SCENARIOS PASSED") {
		t.Errorf("expected ALL SCENARIOS PASSED, got: %s", out)
	}
}

func TestExplainFormatter(t *testing.T) {
	res := sampleResult("E2E-22", "G5", "축소 위임 토큰 쓰기 거부", domain.ExitAuthzDenied, domain.ExitAuthzDenied, true)

	var buf bytes.Buffer
	formatter := NewExplainFormatter(&buf)
	err := formatter.Format([]harness.ScenarioResult{res})
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "시나리오 [E2E-22]") {
		t.Errorf("expected scenario header, got: %s", out)
	}
	if !strings.Contains(out, "[권한 판정] ──▶ 차단") {
		t.Errorf("expected authz blocked cell in diagram, got: %s", out)
	}
	if !strings.Contains(out, "부정 테스트의 역설") {
		t.Errorf("expected paradox explanation, got: %s", out)
	}
}

func TestJSONFormatter(t *testing.T) {
	results := []harness.ScenarioResult{
		sampleResult("E2E-01", "G1", "정상 단일 파일 읽기", domain.ExitSuccess, domain.ExitSuccess, true),
	}

	var buf bytes.Buffer
	formatter := NewJSONFormatter(&buf)
	err := formatter.Format(results)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid json generated: %v", err)
	}

	if report.Total != 1 || report.Passed != 1 || report.Failed != 0 {
		t.Errorf("unexpected report counts: %+v", report)
	}
}

