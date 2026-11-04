package subagent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/parser"
	gotoken "go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
	"authz-harness/internal/jail"
	"authz-harness/internal/subagent"
)

type harnessFixture struct {
	workspaceDir string
	auditPath    string
	keyMgr       keys.KeyManager
	tokenIssuer  token.TokenIssuer
	verifier     token.TokenVerifier
	replayLedger token.ReplayLedger
	papSvc       pap.Service
	pdpSvc       pdp.Service
	jailInst     jail.Jail
	auditWriter  audit.Writer
	gateway      pep.Gateway
	worker       *subagent.SubagentWorker
}

func setupSubagentFixture(t *testing.T) *harnessFixture {
	t.Helper()

	tempDir := t.TempDir()
	workspaceDir := filepath.Join(tempDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatalf("failed to create workspace: %v", err)
	}

	privPath := filepath.Join(tempDir, "signing_keys.priv.json")
	pubPath := filepath.Join(tempDir, "jwks.pub.json")
	replayPath := filepath.Join(tempDir, "replay_ledger.json")
	statePath := filepath.Join(tempDir, "grants_state.json")
	auditPath := filepath.Join(tempDir, "audit.jsonl")

	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("failed to create audit writer: %v", err)
	}
	t.Cleanup(func() {
		_ = auditWriter.Close()
	})

	// 1. Key Manager
	keyStore, err := keys.NewFileStore(privPath, pubPath)
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}
	clock := domain.RealClock{}
	keyMgr, err := keys.NewManager(keyStore, auditWriter)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}
	_, err = keyMgr.RotateKey(domain.AuditContext{TraceID: "init", Actor: "test"})
	if err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}

	// 2. Client Registry & Token Services
	clientReg := token.NewInMemoryClientRegistry()
	replayLedger, err := token.NewFileReplayLedger(replayPath, clock)
	if err != nil {
		t.Fatalf("failed to create replay ledger: %v", err)
	}
	tokenIssuer := token.NewService(keyMgr, clientReg, auditWriter, clock)
	tokenVerifier := token.NewVerifier(keyMgr, replayLedger, auditWriter, clock)

	// 3. PAP & PDP
	stateStore, err := state.NewFileStore(statePath)
	if err != nil {
		t.Fatalf("failed to create state store: %v", err)
	}
	papSvc := pap.NewService(stateStore, auditWriter)
	pipSvc := pip.NewService(stateStore)
	pdpSvc := pdp.NewService(pipSvc, auditWriter)

	// 4. Jail
	jailInst, err := jail.New(workspaceDir)
	if err != nil {
		t.Fatalf("failed to create jail: %v", err)
	}

	// 5. PEP Gateway
	gw, err := pep.NewGateway(pep.Config{
		Verifier:    tokenVerifier,
		PDP:         pdpSvc,
		Jail:        jailInst,
		AuditWriter: auditWriter,
	})
	if err != nil {
		t.Fatalf("failed to create pep gateway: %v", err)
	}

	// 6. Subagent Worker
	worker, err := subagent.NewWorker(gw)
	if err != nil {
		t.Fatalf("failed to create subagent worker: %v", err)
	}

	return &harnessFixture{
		workspaceDir: workspaceDir,
		auditPath:    auditPath,
		keyMgr:       keyMgr,
		tokenIssuer:  tokenIssuer,
		verifier:     tokenVerifier,
		replayLedger: replayLedger,
		papSvc:       papSvc,
		pdpSvc:       pdpSvc,
		jailInst:     jailInst,
		auditWriter:  auditWriter,
		gateway:      gw,
		worker:       worker,
	}
}

func issueTestToken(t *testing.T, f *harnessFixture, subject, scope string) string {
	t.Helper()
	req := token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      subject,
		Audience:     "authz-harness",
		Scope:        scope,
		TTL:          1 * time.Hour,
		Epoch:        1,
	}
	res, err := f.tokenIssuer.IssueToken(req, token.IssueOptions{}, domain.AuditContext{
		TraceID: "issue-token",
		Actor:   subject,
	})
	if err != nil {
		t.Fatalf("failed to issue test token: %v", err)
	}
	return res.TokenString
}

func grantPolicy(t *testing.T, f *harnessFixture, subject string, action domain.Action, resource string) {
	t.Helper()
	_, err := f.papSvc.CreateGrant(context.Background(), pap.CreateGrantRequest{
		Subject:  subject,
		Action:   action,
		Resource: resource,
	})
	if err != nil {
		t.Fatalf("failed to create grant: %v", err)
	}
}

// 10대 표준 인수 테스트 (TC-01 ~ TC-10)

func TestSubagentWorker_TC01_NormalRead(t *testing.T) {
	f := setupSubagentFixture(t)
	sub := "worker-01"
	grantPolicy(t, f, sub, domain.ActionFileRead, "task.txt")
	tok := issueTestToken(t, f, sub, "file:read:task.txt")

	// workspace에 읽을 파일 생성
	testFile := filepath.Join(f.workspaceDir, "task.txt")
	if err := os.WriteFile(testFile, []byte("subagent task contents"), 0644); err != nil {
		t.Fatalf("failed to create task.txt: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-001",
		Token:    tok,
		Action:   "file:read",
		FilePath: "task.txt",
	}

	inBuf := new(bytes.Buffer)
	if err := json.NewEncoder(inBuf).Encode(req); err != nil {
		t.Fatalf("failed to encode req: %v", err)
	}
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitSuccess) {
		t.Fatalf("expected ExitSuccess (0), got: %d, output: %s", exitCode, outBuf.String())
	}

	var resp subagent.SubagentResponse
	if err := json.Unmarshal(outBuf.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ExitCode != 0 || resp.Output != "subagent task contents" || resp.BytesRead != 22 {
		t.Errorf("unexpected response content: %+v", resp)
	}
}

func TestSubagentWorker_TC02_NormalWrite(t *testing.T) {
	f := setupSubagentFixture(t)
	sub := "worker-01"
	grantPolicy(t, f, sub, domain.ActionFileWrite, "out.txt")
	tok := issueTestToken(t, f, sub, "file:write:out.txt")

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-002",
		Token:    tok,
		Action:   "file:write",
		FilePath: "out.txt",
		Data:     "Hello Subagent",
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitSuccess) {
		t.Fatalf("expected ExitSuccess (0), got: %d, output: %s", exitCode, outBuf.String())
	}

	var resp subagent.SubagentResponse
	_ = json.Unmarshal(outBuf.Bytes(), &resp)

	if resp.ExitCode != 0 || resp.BytesWritten != len("Hello Subagent") {
		t.Errorf("unexpected response: %+v", resp)
	}

	// 실제 파일 생성 검증
	saved, err := os.ReadFile(filepath.Join(f.workspaceDir, "out.txt"))
	if err != nil {
		t.Fatalf("failed to read created file: %v", err)
	}
	if string(saved) != "Hello Subagent" {
		t.Errorf("expected 'Hello Subagent', got: %s", string(saved))
	}
}

func TestSubagentWorker_TC03_MissingToken(t *testing.T) {
	f := setupSubagentFixture(t)

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-003",
		Token:    "", // 누락
		Action:   "file:read",
		FilePath: "task.txt",
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitTokenInvalid) {
		t.Fatalf("expected ExitTokenInvalid (11), got: %d", exitCode)
	}

	var resp subagent.SubagentResponse
	_ = json.Unmarshal(outBuf.Bytes(), &resp)
	if resp.ExitCode != int(domain.ExitTokenInvalid) {
		t.Errorf("expected ExitTokenInvalid in response body, got: %d", resp.ExitCode)
	}

	// 감사 로그 파일 검사: 서브에이전트 입구에서 조기 차단되지 않고 PEP 단일 출구 감사를 거쳤는지 검증
	auditBytes, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if !strings.Contains(string(auditBytes), "tr-sub-003") {
		t.Errorf("audit log does not contain trace_id 'tr-sub-003'")
	}
	if !strings.Contains(string(auditBytes), "pep.deny") {
		t.Errorf("audit log does not contain 'pep.deny' event for missing token")
	}
}

func TestSubagentWorker_TC04_ForgedToken(t *testing.T) {
	f := setupSubagentFixture(t)
	sub := "worker-01"

	tokReq := token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      sub,
		Audience:     "authz-harness",
		Scope:        "file:read:task.txt",
		TTL:          10 * time.Minute,
		Epoch:        1,
	}
	res, err := f.tokenIssuer.IssueToken(tokReq, token.IssueOptions{TamperSignature: true}, domain.AuditContext{
		TraceID: "tamper-sig",
		Actor:   sub,
	})
	if err != nil {
		t.Fatalf("failed to issue tampered token: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-004",
		Token:    res.TokenString,
		Action:   "file:read",
		FilePath: "task.txt",
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitTokenInvalid) {
		t.Fatalf("expected ExitTokenInvalid (11), got: %d", exitCode)
	}

	var resp subagent.SubagentResponse
	_ = json.Unmarshal(outBuf.Bytes(), &resp)
	if resp.ExitCode != int(domain.ExitTokenInvalid) {
		t.Errorf("expected ExitTokenInvalid in response body, got: %d", resp.ExitCode)
	}

	// 감사 로그 파일 검사: 서브에이전트 입구에서 조기 차단되지 않고 PEP 단일 출구 감사를 거쳤는지 검증
	auditBytes, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if !strings.Contains(string(auditBytes), "tr-sub-004") {
		t.Errorf("audit log does not contain trace_id 'tr-sub-004'")
	}
	if !strings.Contains(string(auditBytes), "pep.deny") {
		t.Errorf("audit log does not contain 'pep.deny' event for forged token")
	}
}

func TestSubagentWorker_TC05_AuthzDenied_ActionMismatch(t *testing.T) {
	f := setupSubagentFixture(t)
	sub := "worker-01"
	grantPolicy(t, f, sub, domain.ActionFileRead, "attack.txt")
	tok := issueTestToken(t, f, sub, "file:read:attack.txt")

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-005",
		Token:    tok,
		Action:   "file:write", // Read 권한으로 Write 요청
		FilePath: "attack.txt",
		Data:     "malicious content",
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitAuthzDenied) {
		t.Fatalf("expected ExitAuthzDenied (12), got: %d", exitCode)
	}

	// Zero Side-Effect 검증: 파일이 생성되지 않아야 함
	if _, err := os.Stat(filepath.Join(f.workspaceDir, "attack.txt")); !os.IsNotExist(err) {
		t.Errorf("expected attack.txt NOT to be created on deny")
	}
}

func TestSubagentWorker_TC06_PathTraversal(t *testing.T) {
	f := setupSubagentFixture(t)
	sub := "worker-01"
	// Safe grant to pass Gate 2 (PDP), while using symlink escape to trigger Gate 2c (ExitPathViolation)
	safeRes := "symlink_escape.txt"
	grantPolicy(t, f, sub, domain.ActionFileRead, safeRes)
	tok := issueTestToken(t, f, sub, "file:read:"+safeRes)

	outsideDir := filepath.Join(t.TempDir(), "outside")
	_ = os.MkdirAll(outsideDir, 0755)
	outsideTarget := filepath.Join(outsideDir, "secret.txt")
	_ = os.WriteFile(outsideTarget, []byte("outside data"), 0644)

	symlinkPath := filepath.Join(f.workspaceDir, safeRes)
	if err := os.Symlink(outsideTarget, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-006",
		Token:    tok,
		Action:   "file:read",
		FilePath: safeRes, // 심볼릭 링크를 통해 외부 탈출 시도
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitPathViolation) {
		t.Fatalf("expected ExitPathViolation (13), got: %d", exitCode)
	}
}

func TestSubagentWorker_TC07_SymlinkEscape(t *testing.T) {
	f := setupSubagentFixture(t)
	sub := "worker-01"
	grantPolicy(t, f, sub, domain.ActionFileRead, "escape_link")
	tok := issueTestToken(t, f, sub, "file:read:escape_link")

	// Workspace 외부에 민감 파일 생성
	outsideFile := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(outsideFile, []byte("confidential"), 0644)

	// Workspace 내부에 외부 탈출 심볼릭 링크 생성
	linkPath := filepath.Join(f.workspaceDir, "escape_link")
	_ = os.Symlink(outsideFile, linkPath)

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-007",
		Token:    tok,
		Action:   "file:read",
		FilePath: "escape_link",
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitPathViolation) {
		t.Fatalf("expected ExitPathViolation (13), got: %d", exitCode)
	}
}

func TestSubagentWorker_TC08_InvalidJSON(t *testing.T) {
	f := setupSubagentFixture(t)

	inBuf := bytes.NewBufferString("invalid-json-stream{{")
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitBadInput) {
		t.Fatalf("expected ExitBadInput (14), got: %d", exitCode)
	}

	var resp subagent.SubagentResponse
	if err := json.Unmarshal(outBuf.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.ExitCode != int(domain.ExitBadInput) {
		t.Errorf("expected ExitBadInput in response, got: %d", resp.ExitCode)
	}
}

func TestSubagentWorker_TC09_TraceIDChaining(t *testing.T) {
	f := setupSubagentFixture(t)
	sub := "worker-01"
	grantPolicy(t, f, sub, domain.ActionFileWrite, "traced.txt")
	tok := issueTestToken(t, f, sub, "file:write:traced.txt")

	traceID := "tr-chain-test-9999"
	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  traceID,
		Token:    tok,
		Action:   "file:write",
		FilePath: "traced.txt",
		Data:     "trace data",
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := f.worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitSuccess) {
		t.Fatalf("expected ExitSuccess, got: %d", exitCode)
	}

	var resp subagent.SubagentResponse
	_ = json.Unmarshal(outBuf.Bytes(), &resp)
	if resp.TraceID != traceID {
		t.Errorf("expected response trace_id %q, got %q", traceID, resp.TraceID)
	}

	// 감사 로그 파일 검사
	auditBytes, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if !strings.Contains(string(auditBytes), traceID) {
		t.Errorf("audit log does not contain trace_id %q", traceID)
	}
}

func TestSubagentWorker_TC10_FailClosed_AuditFailure(t *testing.T) {
	tok := "some-token"

	mockGW := &mockAuditFailGateway{}
	worker, err := subagent.NewWorker(mockGW)
	if err != nil {
		t.Fatalf("failed to create worker: %v", err)
	}

	req := subagent.SubagentRequest{
		Version:  "1.0",
		TraceID:  "tr-sub-010",
		Token:    tok,
		Action:   "file:write",
		FilePath: "audit_fail.txt",
		Data:     "should never be written",
	}

	inBuf := new(bytes.Buffer)
	_ = json.NewEncoder(inBuf).Encode(req)
	outBuf := new(bytes.Buffer)

	exitCode := worker.ExecuteStream(context.Background(), inBuf, outBuf)
	if exitCode != int(domain.ExitAuditFailure) {
		t.Fatalf("expected ExitAuditFailure (15), got: %d", exitCode)
	}

	var resp subagent.SubagentResponse
	_ = json.Unmarshal(outBuf.Bytes(), &resp)
	if resp.ExitCode != int(domain.ExitAuditFailure) {
		t.Errorf("expected ExitAuditFailure in response, got: %d", resp.ExitCode)
	}
}

type mockAuditFailGateway struct{}

func (m *mockAuditFailGateway) Execute(ctx context.Context, req pep.Request) (*pep.Result, error) {
	return &pep.Result{
		Allowed:  false,
		ExitCode: domain.ExitAuditFailure,
		Reason:   domain.ReasonAuditLogFailed,
		Stage:    pep.Stage4Audit,
		Details:  "injected audit log failure",
	}, nil
}

// TC-040-01: internal/subagent 패키지 의존성 순수성 검증 (AST 검사)
func TestTC_040_01_StrictNoStateStoreImport(t *testing.T) {
	pkgDir := "."
	fset := gotoken.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkgDir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse dir %s: %v", pkgDir, err)
	}

	prohibited := []string{
		"authz-harness/internal/authz/state",
		"authz-harness/internal/authz/pap",
		"authz-harness/internal/authn/keys",
	}

	var violations []string
	for _, pkg := range pkgs {
		for filename, file := range pkg.Files {
			for _, imp := range file.Imports {
				pathVal := strings.Trim(imp.Path.Value, `"`)
				for _, p := range prohibited {
					if pathVal == p {
						violations = append(violations, fmt.Sprintf("%s imports prohibited package %s", filename, pathVal))
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		t.Fatalf("TC-040-01 violations found (subagent package must not import Zone B stores):\n%s", strings.Join(violations, "\n"))
	}
}

// plan-005 AT-01·AT-02·AT-03: 프레임은 모르는 필드를 거부하고(Fail-Closed), 정상 프레임은 이전처럼 실행된다.
func TestSubagentWorker_StrictFrameDecoding(t *testing.T) {
	tests := []struct {
		name       string
		extra      string // 정상 프레임 끝에 덧붙일 JSON 조각
		wantExit   domain.ExitCode
		wantReason string
		wantFile   bool
	}{
		{"AT-01 제거된 inject_revoke_before_io", `,"inject_revoke_before_io":true`, domain.ExitBadInput, string(domain.ReasonInvalidArguments), false},
		{"AT-02 임의의 모르는 필드", `,"foo":1`, domain.ExitBadInput, string(domain.ReasonInvalidArguments), false},
		{"AT-03 기존 필드만 있는 정상 프레임", ``, domain.ExitSuccess, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := setupSubagentFixture(t)
			sub := "worker-strict"
			grantPolicy(t, f, sub, domain.ActionFileWrite, "strict.txt")
			tok := issueTestToken(t, f, sub, "file:write:strict.txt")

			frame := fmt.Sprintf(`{"version":"1.0","trace_id":"tr-strict","token":%q,"action":"file:write","file_path":"strict.txt","data":"x"%s}`, tok, tc.extra)
			outBuf := new(bytes.Buffer)
			exit := f.worker.ExecuteStream(context.Background(), bytes.NewBufferString(frame), outBuf)
			if exit != int(tc.wantExit) {
				t.Fatalf("exit = %d, want %d (out: %s)", exit, tc.wantExit, outBuf.String())
			}
			var resp subagent.SubagentResponse
			if err := json.Unmarshal(outBuf.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if tc.wantReason != "" && resp.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", resp.Reason, tc.wantReason)
			}
			_, statErr := os.Stat(filepath.Join(f.workspaceDir, "strict.txt"))
			if (statErr == nil) != tc.wantFile {
				t.Errorf("file exists = %v, want %v", statErr == nil, tc.wantFile)
			}
			grants, err := f.papSvc.ListGrants(context.Background(), pap.GrantFilter{})
			if err != nil {
				t.Fatalf("list grants: %v", err)
			}
			for _, g := range grants {
				if g.Status != domain.GrantStatusActive {
					t.Errorf("grant %s status = %s, want active", g.ID, g.Status)
				}
			}
		})
	}
}
