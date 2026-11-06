package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
)

type pepCLITestRig struct {
	runner       *PEPRunner
	out          *bytes.Buffer
	errOut       *bytes.Buffer
	workspaceDir string
	statePath    string
	pubJWKSPath  string
	replayPath   string
	auditPath    string
	tokenRunner  *TokenRunner
	grantRunner  *GrantRunner
	keysRunner   *KeysRunner
}

func setupPEPCLITestRig(t *testing.T) *pepCLITestRig {
	t.Helper()
	tmpDir := t.TempDir()

	workspaceDir := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatalf("failed to create workspace dir: %v", err)
	}

	statePath := filepath.Join(tmpDir, "grants_state.json")
	privPath := filepath.Join(tmpDir, "signing_keys.priv.json")
	pubJWKSPath := filepath.Join(tmpDir, "jwks.pub.json")
	replayPath := filepath.Join(tmpDir, "replay_ledger.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	// 1. 키 생성
	keysRunner, err := NewKeysRunner(out, errOut, privPath, pubJWKSPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create keys runner: %v", err)
	}
	if code := keysRunner.Run(context.Background(), []string{"rotate"}); code != domain.ExitSuccess {
		t.Fatalf("failed to rotate keys: %d, err: %s", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()

	// 2. TokenRunner
	tokenRunner, err := NewTokenRunner(out, errOut, privPath, pubJWKSPath, replayPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create token runner: %v", err)
	}

	// 3. GrantRunner
	grantRunner, err := NewGrantRunner(out, errOut, statePath, auditPath)
	if err != nil {
		t.Fatalf("failed to create grant runner: %v", err)
	}

	// 4. PEPRunner
	runner, err := NewPEPRunner(out, errOut, workspaceDir, statePath, pubJWKSPath, replayPath, auditPath)
	if err != nil {
		t.Fatalf("failed to create pep runner: %v", err)
	}

	return &pepCLITestRig{
		runner:       runner,
		out:          out,
		errOut:       errOut,
		workspaceDir: workspaceDir,
		statePath:    statePath,
		pubJWKSPath:  pubJWKSPath,
		replayPath:   replayPath,
		auditPath:    auditPath,
		tokenRunner:  tokenRunner,
		grantRunner:  grantRunner,
		keysRunner:   keysRunner,
	}
}

// tokenJTIForLog 는 서명 검증 없이 토큰 페이로드에서 jti 만 꺼낸다(시험 로그 전용).
// 꺼내지 못하면 토큰 내용을 노출하지 않는 자리표시자를 돌려준다.
func tokenJTIForLog(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "<unparsable>"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "<unparsable>"
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.JTI == "" {
		return "<unparsable>"
	}
	return claims.JTI
}

// issueToken 은 테스트 헬퍼로 토큰을 발급받아 반환한다.
func (rig *pepCLITestRig) issueToken(t *testing.T, sub, scope, aud string) string {
	t.Helper()
	rig.out.Reset()
	rig.errOut.Reset()

	issueArgs := []string{
		"issue",
		"--client-id", "client-orchestrator",
		"--client-secret", "orchestrator-secret-key-01",
		"--sub", sub,
		"--scope", scope,
		"--aud", aud,
	}

	code := rig.tokenRunner.Run(context.Background(), issueArgs)
	if code != domain.ExitSuccess {
		t.Fatalf("failed to issue token: %d, err: %s", code, rig.errOut.String())
	}

	lines := strings.Split(strings.TrimSpace(rig.out.String()), "\n")
	tok := strings.TrimSpace(lines[len(lines)-1])
	// 원시 토큰은 로그에 남기지 않고 jti 만 기록한다 (AGENTS.md §3 Zero Leakage)
	t.Logf("issued token for %s (%s): jti=%s", sub, scope, tokenJTIForLog(tok))

	rig.out.Reset()
	rig.errOut.Reset()
	return tok
}

// createGrant 는 테스트 헬퍼로 Grant를 등록한다.
func (rig *pepCLITestRig) createGrant(t *testing.T, sub, role, action, resource string) {
	t.Helper()
	rig.createGrantID(t, sub, role, action, resource)
}

// createGrantID 는 Grant 를 만들고 출력에서 파싱한 Grant ID 를 돌려준다.
func (rig *pepCLITestRig) createGrantID(t *testing.T, sub, role, action, resource string) string {
	t.Helper()
	rig.out.Reset()
	rig.errOut.Reset()

	createArgs := []string{
		"create",
		"--sub", sub,
		"--action", action,
		"--resource", resource,
	}

	code := rig.grantRunner.Run(context.Background(), createArgs)
	if code != domain.ExitSuccess {
		t.Fatalf("failed to create grant: %d, err: %s", code, rig.errOut.String())
	}
	head := strings.TrimSpace(strings.Split(rig.out.String(), "|")[0])
	toks := strings.Split(head, "ID: ")
	if len(toks) < 2 {
		t.Fatalf("failed to parse grant ID from stdout: %s", rig.out.String())
	}
	id := strings.TrimSpace(toks[1])
	rig.out.Reset()
	rig.errOut.Reset()
	return id
}

// revokeGrant 는 PAP(grant revoke)로 Grant 를 회수한다.
func (rig *pepCLITestRig) revokeGrant(t *testing.T, id string) {
	t.Helper()
	if code := rig.grantRunner.Run(context.Background(), []string{"revoke", "--id", id}); code != domain.ExitSuccess {
		t.Fatalf("failed to revoke grant: %d, err: %s", code, rig.errOut.String())
	}
	rig.out.Reset()
	rig.errOut.Reset()
}

func TestPEPCLI_AcceptanceScenarios(t *testing.T) {
	tests := []struct {
		id           string
		name         string
		setup        func(t *testing.T, rig *pepCLITestRig) []string
		expectedExit domain.ExitCode
		verify       func(t *testing.T, rig *pepCLITestRig)
	}{
		{
			id:   "AC-01",
			name: "정상 파일 쓰기 (유효한 write 토큰 및 경로)",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				rig.createGrant(t, "worker-01", "operator", "file:write", "reports/summary.txt")
				tok := rig.issueToken(t, "worker-01", "file:write", "authz-harness")
				return []string{
					"write", "reports/summary.txt",
					"--token", tok,
					"--data", "hello AC-01",
				}
			},
			expectedExit: domain.ExitSuccess,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				filePath := filepath.Join(rig.workspaceDir, "reports/summary.txt")
				data, err := os.ReadFile(filePath)
				if err != nil {
					t.Fatalf("file should exist: %v", err)
				}
				if string(data) != "hello AC-01" {
					t.Fatalf("expected 'hello AC-01', got: %s", string(data))
				}
				if !strings.Contains(rig.out.String(), "[PASS]") {
					t.Fatalf("expected pipeline PASS, got:\n%s", rig.out.String())
				}
			},
		},
		{
			id:   "AC-02",
			name: "정상 파일 읽기 (유효한 read 토큰 및 기존 파일 존재)",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				targetFile := filepath.Join(rig.workspaceDir, "notes.txt")
				if err := os.WriteFile(targetFile, []byte("content of notes"), 0644); err != nil {
					t.Fatalf("failed to setup notes file: %v", err)
				}
				rig.createGrant(t, "worker-02", "reader", "file:read", "notes.txt")
				tok := rig.issueToken(t, "worker-02", "file:read:notes.txt", "authz-harness")
				return []string{
					"read", "notes.txt",
					"--token", tok,
				}
			},
			expectedExit: domain.ExitSuccess,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				if !strings.Contains(rig.out.String(), "content of notes") {
					t.Fatalf("expected output to contain file content, got:\n%s", rig.out.String())
				}
			},
		},
		{
			id:   "AC-03",
			name: "유효하지 않은 토큰 거부",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				return []string{
					"read", "notes.txt",
					"--token", "invalid.jwt.token",
				}
			},
			expectedExit: domain.ExitTokenInvalid,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				if !strings.Contains(rig.out.String(), "[FAIL]") {
					t.Fatalf("expected authn 단계 FAIL, got:\n%s", rig.out.String())
				}
			},
		},
		{
			id:   "AC-04",
			name: "토큰 Replay 재사용 거부",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				rig.createGrant(t, "worker-04", "writer", "file:write", "replay.txt")
				tok := rig.issueToken(t, "worker-04", "file:write", "authz-harness")

				// 1회차 성공
				code1 := rig.runner.Run(context.Background(), []string{"write", "replay.txt", "--token", tok, "--data", "run 1"})
				if code1 != domain.ExitSuccess {
					t.Fatalf("run 1 should succeed: %d", code1)
				}
				rig.out.Reset()
				rig.errOut.Reset()

				// 2회차 재사용 시도
				return []string{
					"write", "replay.txt",
					"--token", tok,
					"--data", "run 2",
				}
			},
			expectedExit: domain.ExitTokenInvalid,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				// 파일 내용이 여전히 1회차 내용이어야 함 (0바이트 부작용)
				data, err := os.ReadFile(filepath.Join(rig.workspaceDir, "replay.txt"))
				if err != nil {
					t.Fatalf("file read failed: %v", err)
				}
				if string(data) != "run 1" {
					t.Fatalf("expected data to remain 'run 1', got: %s", string(data))
				}
			},
		},
		{
			id:   "AC-05",
			name: "Scope 권한 불일치 거부 (read 토큰으로 write 시도)",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				rig.createGrant(t, "worker-05", "reader", "file:read", "data.txt")
				tok := rig.issueToken(t, "worker-05", "file:read", "authz-harness")
				return []string{
					"write", "data.txt",
					"--token", tok,
					"--data", "unauthorized write",
				}
			},
			expectedExit: domain.ExitAuthzDenied,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				// 파일이 생성되지 않아야 함
				if _, err := os.Stat(filepath.Join(rig.workspaceDir, "data.txt")); !os.IsNotExist(err) {
					t.Fatalf("file should not exist on deny")
				}
			},
		},
		{
			id:   "AC-06",
			name: "Grant 부재 거부",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				// Grant 등록 없음
				tok := rig.issueToken(t, "ghost-worker", "file:read", "authz-harness")
				return []string{
					"read", "foo.txt",
					"--token", tok,
				}
			},
			expectedExit: domain.ExitAuthzDenied,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				if !strings.Contains(rig.out.String(), "DENY") {
					t.Fatalf("expected DENY output, got:\n%s", rig.out.String())
				}
			},
		},
		{
			id:   "AC-07",
			name: "상위 경로 탈출 시도 차단",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				// Workspace 내부에 외부를 가리키는 symlink 생성하여 심볼릭 링크 기반 탈출 시도
				outsideFile := filepath.Join(t.TempDir(), "target_outside.txt")
				_ = os.WriteFile(outsideFile, []byte("outside"), 0644)
				symlinkPath := filepath.Join(rig.workspaceDir, "escape_link.txt")
				_ = os.Symlink(outsideFile, symlinkPath)

				rig.createGrant(t, "worker-07", "admin", "file:write", "escape_link.txt")
				tok := rig.issueToken(t, "worker-07", "file:write", "authz-harness")
				return []string{
					"write", "escape_link.txt",
					"--token", tok,
					"--data", "root::0:0",
				}
			},
			expectedExit: domain.ExitPathViolation,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				if !strings.Contains(rig.out.String(), "ExitPathViolation") {
					t.Fatalf("expected ExitPathViolation in output, got:\n%s", rig.out.String())
				}
			},
		},
		{
			id:   "AC-08",
			name: "외부 심볼릭 링크 탈출 차단",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				// Workspace 외부에 민감 파일 생성
				outsideFile := filepath.Join(t.TempDir(), "outside_secret.txt")
				if err := os.WriteFile(outsideFile, []byte("super-secret"), 0644); err != nil {
					t.Fatalf("failed to create outside secret: %v", err)
				}

				// Workspace 내부에 외부를 가리키는 symlink 생성
				symlinkPath := filepath.Join(rig.workspaceDir, "leak_link.txt")
				if err := os.Symlink(outsideFile, symlinkPath); err != nil {
					t.Fatalf("failed to create symlink: %v", err)
				}

				rig.createGrant(t, "worker-08", "admin", "file:read", "leak_link.txt")
				tok := rig.issueToken(t, "worker-08", "file:read", "authz-harness")

				return []string{
					"read", "leak_link.txt",
					"--token", tok,
				}
			},
			expectedExit: domain.ExitPathViolation,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				if strings.Contains(rig.out.String(), "super-secret") {
					t.Fatalf("outside secret leaked!")
				}
			},
		},
		{
			id:   "AC-09",
			name: "사전 커밋 감사 결함 주입 시 Fail-Closed 쓰기 차단",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				rig.createGrant(t, "worker-09", "operator", "file:write", "critical.txt")
				tok := rig.issueToken(t, "worker-09", "file:write", "authz-harness")
				return []string{
					"write", "critical.txt",
					"--token", tok,
					"--data", "must not be written",
					"--inject-audit-failure",
				}
			},
			expectedExit: domain.ExitAuditFailure,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				// 파일이 생성되지 않고 0바이트 유지
				if _, err := os.Stat(filepath.Join(rig.workspaceDir, "critical.txt")); !os.IsNotExist(err) {
					t.Fatalf("file must not be created on audit failure")
				}
				if !strings.Contains(rig.out.String(), "ExitAuditFailure") {
					t.Fatalf("expected ExitAuditFailure in output, got:\n%s", rig.out.String())
				}
			},
		},
		{
			id:   "AC-10",
			name: "필수 인자 누락 거부 (--token 플래그 누락)",
			setup: func(t *testing.T, rig *pepCLITestRig) []string {
				return []string{
					"read", "foo.txt",
				}
			},
			expectedExit: domain.ExitBadInput,
			verify: func(t *testing.T, rig *pepCLITestRig) {
				if !strings.Contains(rig.errOut.String(), "missing required --token") {
					t.Fatalf("expected missing token error, got:\n%s", rig.errOut.String())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.id+"_"+tc.name, func(t *testing.T) {
			rig := setupPEPCLITestRig(t)
			args := tc.setup(t, rig)
			rig.out.Reset()
			rig.errOut.Reset()

			code := rig.runner.Run(context.Background(), args)
			if code != tc.expectedExit {
				t.Fatalf("[%s] expected exit code %d, got %d. stderr:\n%s\nstdout:\n%s",
					tc.id, tc.expectedExit, code, rig.errOut.String(), rig.out.String())
			}

			if tc.verify != nil {
				tc.verify(t, rig)
			}
		})
	}
}

func TestPEPCLI_JSONOutputFormat(t *testing.T) {
	rig := setupPEPCLITestRig(t)
	rig.createGrant(t, "worker-json", "admin", "file:write", "output.json")
	tok := rig.issueToken(t, "worker-json", "file:write:output.json", "authz-harness")

	args := []string{
		"write", "output.json",
		"--token", tok,
		"--data", `{"hello":"world"}`,
		"--output-format", "json",
	}

	code := rig.runner.Run(context.Background(), args)
	if code != domain.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got %d. err: %s", code, rig.errOut.String())
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(rig.out.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse json output: %v, raw: %s", err, rig.out.String())
	}

	if parsed["allowed"] != true {
		t.Fatalf("expected allowed true, got: %v", parsed["allowed"])
	}
	if parsed["exit_code"] != float64(domain.ExitSuccess) {
		t.Fatalf("expected exit_code %d, got: %v", domain.ExitSuccess, parsed["exit_code"])
	}
}

// 계획 014 N4 (구 TC-030-06 대체): 화면의 종료 코드 이름은 domain 이 정한 이름을 그대로 쓴다.
// 이름 표 자체의 검증(ExitResourceLimit 포함 모든 코드)은 domain.TestExitCodeName_* 가 맡는다.
func TestPEPCLI_RenderResult_ShowsDomainExitCodeName(t *testing.T) {
	tests := []struct {
		name     string
		exitCode domain.ExitCode
		want     string
	}{
		{"승인 대기", domain.ExitApprovalRequired, "EXIT CODE: 18 (ExitApprovalRequired)"},
		{"자원 한계", domain.ExitResourceLimit, "EXIT CODE: 17 (ExitResourceLimit)"},
		{"정의되지 않은 값", domain.ExitCode(99), "EXIT CODE: 99 (Unknown)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rig := setupPEPCLITestRig(t)
			rig.out.Reset()
			rig.runner.renderResult(pep.Request{Action: domain.ActionFileRead, Resource: "x.txt"},
				&pep.Result{Allowed: false, ExitCode: tc.exitCode, Reason: domain.ReasonApprovalRequired}, "")
			if !strings.Contains(rig.out.String(), tc.want) {
				t.Fatalf("want %q in output:\n%s", tc.want, rig.out.String())
			}
		})
	}
}

// TC-010-07: pep CLI 는 음수 --clock-offset 을 PEP 호출 없이 ExitBadInput 으로 거부하고, 양수는 기존대로 동작한다.
func TestPEPCLI_ClockOffsetNegativeRejected(t *testing.T) {
	cases := []struct {
		name   string
		offset string
		want   domain.ExitCode
	}{
		{"음수 -10m 거부", "-10m", domain.ExitBadInput},
		{"양수 10s 허용", "10s", domain.ExitSuccess},
	}
	for _, tc := range cases {
		for _, op := range []string{"read", "write"} {
			t.Run(tc.name+"/"+op, func(t *testing.T) {
				rig := setupPEPCLITestRig(t)
				if err := os.WriteFile(filepath.Join(rig.workspaceDir, "n.txt"), []byte("x"), 0644); err != nil {
					t.Fatalf("setup: %v", err)
				}
				action := "file:" + op
				rig.createGrant(t, "w-clock", "r", action, "n.txt")
				tok := rig.issueToken(t, "w-clock", action+":n.txt", "authz-harness")
				args := []string{op, "n.txt", "--token", tok, "--clock-offset", tc.offset}
				if op == "write" {
					args = append(args, "--data", "y")
				}
				if got := rig.runner.Run(context.Background(), args); got != tc.want {
					t.Fatalf("exit = %d, want %d, stderr: %s", got, tc.want, rig.errOut.String())
				}
			})
		}
	}
}
