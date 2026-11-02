package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/ui"
)

func TestRunCLI_AT_CLI_01_AllScenarios(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	start := time.Now()
	exitCode := runner.Run(context.Background(), []string{"-scenario", "all"})
	duration := time.Since(start)

	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}

	outStr := out.String()
	if !strings.Contains(outStr, "ALL SCENARIOS PASSED") {
		t.Errorf("expected 'ALL SCENARIOS PASSED', got:\n%s", outStr)
	}

	// AT-CLI-07: 60초 이내 완주 (실제 5초 이내)
	if duration > 60*time.Second {
		t.Errorf("expected execution time under 60s, got %v", duration)
	}
}

func TestRunCLI_AT_CLI_02_ExplainOutput(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{"-scenario", "E2E-22", "-output-format", "explain"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}

	outStr := out.String()
	if !strings.Contains(outStr, "시나리오 [E2E-22]") {
		t.Errorf("expected E2E-22 header in explain output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Gate 2: 위임 & 스코프") {
		t.Errorf("expected Gate 2 in diagram, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "부정 테스트의 역설") {
		t.Errorf("expected paradox section, got:\n%s", outStr)
	}
}

func TestRunCLI_AT_CLI_03_GroupFilter(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{"-group", "G5"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}

	outStr := out.String()
	if !strings.Contains(outStr, "E2E-19") || !strings.Contains(outStr, "E2E-24") {
		t.Errorf("expected G5 scenarios in output, got:\n%s", outStr)
	}
	// G1 시나리오는 포함되지 않아야 함
	if strings.Contains(outStr, "E2E-01") {
		t.Errorf("G1 scenario should not be in G5 group run")
	}
}

func TestRunCLI_AT_CLI_04_JSONOutput(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{"-output-format", "json"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}

	var report ui.JSONReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse json output: %v", err)
	}

	if report.Total != 32 {
		t.Errorf("expected 32 total scenarios in json, got %d", report.Total)
	}
	if report.Passed != 32 {
		t.Errorf("expected 32 passed scenarios, got %d", report.Passed)
	}
	if report.Failed != 0 {
		t.Errorf("expected 0 failed scenarios, got %d", report.Failed)
	}
}

func TestRunCLI_AT_CLI_05_UnknownScenario(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{"-scenario", "E2E-99"})
	if exitCode != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput (2), got %v", exitCode)
	}

	if !strings.Contains(errOut.String(), "E2E-99") {
		t.Errorf("expected error message mentioning E2E-99, got: %s", errOut.String())
	}
}

func TestRunCLI_AT_CLI_06_FailFast(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	// -fail-fast 옵션 플래그가 정상 파싱되고 전수 정상 시 0으로 통과하는지 검증
	exitCode := runner.Run(context.Background(), []string{"-scenario", "all", "-fail-fast"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got %v", exitCode)
	}
}

func TestRunCLI_AT_CLI_08_TriSeparation(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{"-scenario", "E2E-01", "-output-format", "explain", "-verbose"})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got %v", exitCode)
	}

	// stdout 에는 포맷팅된 결과 출력
	if !strings.Contains(out.String(), "시나리오 [E2E-01]") {
		t.Errorf("expected E2E-01 output in stdout")
	}

	// errOut 에는 포맷팅 결과가 섞여 들어가지 않아야 함 (Tri-Separation)
	if strings.Contains(errOut.String(), "시나리오 [E2E-01]") {
		t.Errorf("stdout UI output leaked into stderr")
	}
}

// TC-020-01: authz-harness run --scenario E2E-01 --execution-mode subprocess 성공 검증
func TestRunCLI_TC_020_01_SubprocessMode_E2E01(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{
		"-scenario", "E2E-01",
		"-execution-mode", "subprocess",
	})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "ALL SCENARIOS PASSED") {
		t.Errorf("expected 'ALL SCENARIOS PASSED', got:\n%s", out.String())
	}
}

// TC-020-02: authz-harness run --scenario E2E-22 --execution-mode subprocess 성공 검증
func TestRunCLI_TC_020_02_SubprocessMode_E2E22(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{
		"-scenario", "E2E-22",
		"-execution-mode", "subprocess",
	})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "ALL SCENARIOS PASSED") {
		t.Errorf("expected 'ALL SCENARIOS PASSED', got:\n%s", out.String())
	}
}

// TC-020-03: authz-harness run --execution-mode inproc 플래그 호환 검증
func TestRunCLI_TC_020_03_InProcMode(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{
		"-scenario", "E2E-01",
		"-execution-mode", "inproc",
	})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "ALL SCENARIOS PASSED") {
		t.Errorf("expected 'ALL SCENARIOS PASSED', got:\n%s", out.String())
	}
}

// TC-030-01: authz-harness run --scenario E2E-31 --execution-mode subprocess 다단계 정상 위임
func TestRunCLI_TC_030_01_MultiHopAllow(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{
		"-scenario", "E2E-31",
		"-execution-mode", "subprocess",
	})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "ALL SCENARIOS PASSED") {
		t.Errorf("expected 'ALL SCENARIOS PASSED', got:\n%s", out.String())
	}
}

// TC-030-02: authz-harness run --scenario E2E-32 --execution-mode subprocess 중간 초과 위임 차단
func TestRunCLI_TC_030_02_MultiHopScopeExceeded(t *testing.T) {
	tempDir := t.TempDir()
	var out, errOut bytes.Buffer
	runner := NewRunRunner(&out, &errOut, tempDir)

	exitCode := runner.Run(context.Background(), []string{
		"-scenario", "E2E-32",
		"-execution-mode", "subprocess",
	})
	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess (0), got %v. Stderr: %s", exitCode, errOut.String())
	}
	if !strings.Contains(out.String(), "ALL SCENARIOS PASSED") {
		t.Errorf("expected 'ALL SCENARIOS PASSED', got:\n%s", out.String())
	}
}
