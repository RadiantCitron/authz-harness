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
	if !strings.Contains(out, "Gate 2: 위임 & 스코프") {
		t.Errorf("expected Gate 2 in diagram, got: %s", out)
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

func TestComputePipelineGates(t *testing.T) {
	// 1. Success 시나리오 -> 6개 전 관문 통과
	succRes := sampleResult("E2E-01", "G1", "정상 읽기", domain.ExitSuccess, domain.ExitSuccess, true)
	gates := ComputePipelineGates(succRes)
	if len(gates) != 6 {
		t.Fatalf("expected 6 gates, got %d", len(gates))
	}
	for i, g := range gates {
		if g.Status != GatePass {
			t.Errorf("gate %d expected PASS, got %s", i, g.Status)
		}
	}

	// 2. E2E-22 시나리오 -> Gate 0, 1 PASS, Gate 2 BLOCKED, Gate 3, 4, 5 SKIPPED
	res22 := sampleResult("E2E-22", "G5", "위임 스코프 차단", domain.ExitAuthzDenied, domain.ExitAuthzDenied, true)
	gates22 := ComputePipelineGates(res22)
	if gates22[0].Status != GatePass || gates22[1].Status != GatePass {
		t.Errorf("Gate 0 and 1 should PASS")
	}
	if gates22[2].Status != GateBlocked {
		t.Errorf("Gate 2 should be BLOCKED, got %s", gates22[2].Status)
	}
	if gates22[3].Status != GateSkipped || gates22[4].Status != GateSkipped || gates22[5].Status != GateSkipped {
		t.Errorf("Gates 3, 4, 5 should be SKIPPED")
	}
}
