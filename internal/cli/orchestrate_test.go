package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/domain"
)

var (
	builtBinaryPath string
	buildOnce       sync.Once
	buildErr        error
)

func getTestBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "orch-cli-test-*")
		if err != nil {
			buildErr = err
			return
		}
		binPath := filepath.Join(tmpDir, "authz-harness")
		cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/authz-harness")
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("failed to build authz-harness binary: %v (output: %s)", err, string(out))
			return
		}
		builtBinaryPath = binPath
	})

	if buildErr != nil {
		t.Fatalf("failed to prepare test binary: %v", buildErr)
	}
	return builtBinaryPath
}

func TestOrchestrateRunner_TC06_NormalSpawn(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	// 준비: Grant 및 파일 생성
	testFile := "spawn_read.txt"
	absPath := filepath.Join(rig.workspaceDir, testFile)
	if err := os.WriteFile(absPath, []byte("orchestrated content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	sub := "subagent-worker-06"
	rig.createGrant(t, sub, "operator", "file:read", testFile)
	tok := rig.issueToken(t, sub, "file:read", "authz-harness")

	runner, err := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create orchestrate runner: %v", err)
	}
	runner.SetWorkerBinaryPath(bin)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{
		"spawn",
		"-token", tok,
		"-action", "file:read",
		"-file", testFile,
		"-trace-id", "tr-orch-06",
	})

	if exitCode != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got: %d (stderr: %s, stdout: %s)", exitCode, rig.errOut.String(), rig.out.String())
	}

	stdoutStr := rig.out.String()
	if !strings.Contains(stdoutStr, "Trace ID: tr-orch-06") {
		t.Errorf("stdout missing Trace ID, got: %s", stdoutStr)
	}
	if !strings.Contains(stdoutStr, "orchestrated content") {
		t.Errorf("stdout missing file content, got: %s", stdoutStr)
	}
}

func TestOrchestrateRunner_TC07_MissingRequiredArgs(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	runner, err := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create orchestrate runner: %v", err)
	}
	runner.SetWorkerBinaryPath(bin)

	// -token 누락
	rig.out.Reset()
	rig.errOut.Reset()
	code := runner.Run(context.Background(), []string{"spawn", "-file", "file.txt"})
	if code != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput(2) when token missing, got: %d", code)
	}

	// -file 누락
	rig.out.Reset()
	rig.errOut.Reset()
	code = runner.Run(context.Background(), []string{"spawn", "-token", "some.jwt.token"})
	if code != domain.ExitBadInput {
		t.Errorf("expected ExitBadInput(2) when file missing, got: %d", code)
	}
}

// plan-005 AT-04: 결함 주입 플래그는 정의되지 않은 플래그로 거부되고 자식은 기동되지 않는다.
// 유효한 Grant·토큰을 준비해, 플래그가 무시된다면 쓰기가 성공했을 상황에서 거부됨을 확인한다.
func TestOrchestrateRunner_AT04_RejectsRemovedInjectFlag(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	testFile := "at04_target.txt"
	sub := "subagent-worker-at04"
	rig.createGrant(t, sub, "operator", "file:write", testFile)
	tok := rig.issueToken(t, sub, "file:write", "authz-harness")

	runner, err := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create orchestrate runner: %v", err)
	}
	runner.SetWorkerBinaryPath(bin)

	auditBefore, err := os.ReadFile(rig.auditPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read audit: %v", err)
	}

	rig.out.Reset()
	rig.errOut.Reset()
	code := runner.Run(context.Background(), []string{
		"spawn",
		"-token", tok,
		"-action", "file:write",
		"-file", testFile,
		"-data", "must not be written",
		"-inject-revoke-before-io",
		"-trace-id", "tr-orch-at04",
	})
	if code != domain.ExitBadInput {
		t.Fatalf("expected ExitBadInput(%d), got: %d (stderr: %s)", domain.ExitBadInput, code, rig.errOut.String())
	}
	if !strings.Contains(rig.errOut.String(), "inject-revoke-before-io") {
		t.Errorf("stderr should name the undefined flag, got: %s", rig.errOut.String())
	}

	// 자식 미기동: 대상 파일 미생성, 부모 사전·사후 감사(스폰 기록) 추가 없음
	if _, err := os.Stat(filepath.Join(rig.workspaceDir, testFile)); !os.IsNotExist(err) {
		t.Errorf("target file must not exist when flag is rejected")
	}
	auditAfter, err := os.ReadFile(rig.auditPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read audit: %v", err)
	}
	if string(auditAfter) != string(auditBefore) {
		t.Errorf("audit log must be unchanged (no spawn), grew by %d bytes", len(auditAfter)-len(auditBefore))
	}
}

func TestOrchestrateRunner_TC08_HarvestDeniedExitCode(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	// Grant 없는 파일에 대한 쓰기 시도 -> 자식이 12 반환 -> 부모도 12 수거 및 반환
	sub := "subagent-worker-08"
	tok := rig.issueToken(t, sub, "file:read", "authz-harness")

	runner, err := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create orchestrate runner: %v", err)
	}
	runner.SetWorkerBinaryPath(bin)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{
		"spawn",
		"-token", tok,
		"-action", "file:write",
		"-file", "no_grant_write.txt",
		"-data", "should fail",
		"-trace-id", "tr-orch-08",
	})

	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied(12), got: %d (stdout: %s, stderr: %s)", exitCode, rig.out.String(), rig.errOut.String())
	}

	// 자식 에러 문구 및 종료 코드 12 수거 검증
	stdoutStr := rig.out.String()
	if !strings.Contains(stdoutStr, "Child Exit Code: 12") {
		t.Errorf("expected Child Exit Code: 12 in stdout, got: %s", stdoutStr)
	}

	// 파일 미생성 확인
	absPath := filepath.Join(rig.workspaceDir, "no_grant_write.txt")
	if _, err := os.Stat(absPath); !os.IsNotExist(err) {
		t.Errorf("file should not exist on authz denial")
	}
}

func TestOrchestrateRunner_TC09_RevokedBeforeSpawn(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	// 준비: Grant 및 쓰기 대상 파일 준비
	testFile := "toctou_target.txt"
	sub := "subagent-worker-09"
	gid := rig.createGrantID(t, sub, "operator", "file:write", testFile)
	tok := rig.issueToken(t, sub, "file:write", "authz-harness")
	// 토큰 발급 뒤 PAP 로 Grant 회수 — 자식은 공유 장부에서 회수를 봐야 한다
	rig.revokeGrant(t, gid)

	runner, err := NewOrchestrateRunner(rig.out, rig.errOut, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
	if err != nil {
		t.Fatalf("failed to create orchestrate runner: %v", err)
	}
	runner.SetWorkerBinaryPath(bin)

	rig.out.Reset()
	rig.errOut.Reset()
	exitCode := runner.Run(context.Background(), []string{
		"spawn",
		"-token", tok,
		"-action", "file:write",
		"-file", testFile,
		"-data", "race injection attack data",
		"-trace-id", "tr-orch-toctou-09",
	})

	// TOCTOU 방어 검증: 자식이 Gate 2에서 Grant 회수 감지 -> Exit Code 12 거부
	if exitCode != domain.ExitAuthzDenied {
		t.Fatalf("expected ExitAuthzDenied(12), got: %d (stdout: %s, stderr: %s)", exitCode, rig.out.String(), rig.errOut.String())
	}

	// 파일 수정 0바이트 검증
	absPath := filepath.Join(rig.workspaceDir, testFile)
	if _, err := os.Stat(absPath); !os.IsNotExist(err) {
		t.Errorf("file should not be created or written when revoked before io")
	}
}

func TestOrchestrateRunner_TC10_SingleAuditChain_And_Concurrency(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	bin := getTestBinary(t)

	const concurrency = 5

	type workerJob struct {
		sub   string
		file  string
		token string
	}

	// 사전 준비: 토큰 발급 및 Grant 생성은 순차적으로 수행 (공유 테스트 버퍼 레이스 방지)
	jobs := make([]workerJob, concurrency)
	for i := 0; i < concurrency; i++ {
		sub := fmt.Sprintf("worker-concurr-%d", i)
		file := fmt.Sprintf("concurr_%d.txt", i)

		rig.createGrant(t, sub, "operator", "file:read", file)
		tok := rig.issueToken(t, sub, "file:read", "authz-harness")

		absFile := filepath.Join(rig.workspaceDir, file)
		if err := os.WriteFile(absFile, []byte(fmt.Sprintf("data-%d", i)), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		jobs[i] = workerJob{
			sub:   sub,
			file:  file,
			token: tok,
		}
	}

	// 병렬 실행: 각 고루틴은 독립된 버퍼와 OrchestrateRunner로 실제 독립 서브프로세스 스폰
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		idx := i
		job := jobs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()

			outBuf := &bytes.Buffer{}
			errBuf := &bytes.Buffer{}

			runner, err := NewOrchestrateRunner(outBuf, errBuf, rig.workspaceDir, rig.statePath, rig.pubJWKSPath, rig.replayPath, rig.auditPath)
			if err != nil {
				errCh <- fmt.Errorf("worker %d: runner create err: %w", idx, err)
				return
			}
			runner.SetWorkerBinaryPath(bin)

			traceID := fmt.Sprintf("tr-concurr-%d-%d", idx, time.Now().UnixNano())
			code := runner.Run(context.Background(), []string{
				"spawn",
				"-token", job.token,
				"-action", "file:read",
				"-file", job.file,
				"-trace-id", traceID,
			})

			if code != domain.ExitSuccess {
				errCh <- fmt.Errorf("worker %d: unexpected exit code %d (err: %s)", idx, code, errBuf.String())
				return
			}

			if !strings.Contains(outBuf.String(), fmt.Sprintf("data-%d", idx)) {
				errCh <- fmt.Errorf("worker %d: content mismatch: %s", idx, outBuf.String())
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrency error: %v", err)
	}

	// 감사 로그 파일 단일 체인 및 무결성 검증
	auditBytes, err := os.ReadFile(rig.auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}

	auditContent := string(auditBytes)
	if !strings.Contains(auditContent, "ORCHESTRATE_SPAWN") {
		t.Errorf("audit log missing ORCHESTRATE_SPAWN")
	}
	if !strings.Contains(auditContent, "pep-gateway") {
		t.Errorf("audit log missing pep-gateway events")
	}
}
