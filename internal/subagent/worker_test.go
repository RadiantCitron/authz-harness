package subagent_test

import (
	"bytes"
	"context"
	"encoding/json"
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
