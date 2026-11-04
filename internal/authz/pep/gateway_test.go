package pep_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	"authz-harness/internal/observe/slogadapter"
)

type testHarness struct {
	workspaceDir string
	auditFile    string
	keyMgr       keys.KeyManager
	tokenIssuer  token.TokenIssuer
	verifier     token.TokenVerifier
	replayLedger token.ReplayLedger
	papSvc       pap.Service
	pdpSvc       pdp.Service
	jailInst     jail.Jail
	auditWriter  audit.Writer
	gateway      pep.Gateway
	store        state.Store
}

func setupTestHarness(t *testing.T) *testHarness {
	t.Helper()

	tempDir := t.TempDir()
	workspaceDir := filepath.Join(tempDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatalf("failed to create workspace dir: %v", err)
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
		t.Fatalf("failed to init key: %v", err)
	}

	// 2. Token Issuer & Verifier
	replayLedger, err := token.NewFileReplayLedger(replayPath, clock)
	if err != nil {
		t.Fatalf("failed to create replay ledger: %v", err)
	}
	clients := token.NewInMemoryClientRegistry()
	tokenIssuer := token.NewService(keyMgr, clients, auditWriter, clock)
	tokenVerifier := token.NewVerifier(keyMgr, replayLedger, auditWriter, clock)

	// 3. PAP & PDP
	store, err := state.NewFileStore(statePath)
	if err != nil {
		t.Fatalf("failed to create state store: %v", err)
	}
	papSvc := pap.NewService(store, auditWriter)
	pipSvc := pip.NewService(store)
	pdpSvc := pdp.NewService(pipSvc, auditWriter)

	// 4. Jail
	jailInst, err := jail.New(workspaceDir)
	if err != nil {
		t.Fatalf("failed to init jail: %v", err)
	}

	// 5. PEP Gateway
	gw, err := pep.NewGateway(pep.Config{
		Verifier:    tokenVerifier,
		PDP:         pdpSvc,
		Jail:        jailInst,
		AuditWriter: auditWriter,
	})
	if err != nil {
		t.Fatalf("failed to init pep gateway: %v", err)
	}

	return &testHarness{
		workspaceDir: workspaceDir,
		auditFile:    auditPath,
		keyMgr:       keyMgr,
		tokenIssuer:  tokenIssuer,
		verifier:     tokenVerifier,
		replayLedger: replayLedger,
		papSvc:       papSvc,
		pdpSvc:       pdpSvc,
		jailInst:     jailInst,
		auditWriter:  auditWriter,
		gateway:      gw,
		store:        store,
	}
}

func issueValidToken(t *testing.T, h *testHarness, subject, scope string, ttl time.Duration, epoch domain.Epoch) string {
	t.Helper()
	req := token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      subject,
		Audience:     "authz-harness",
		Scope:        scope,
		TTL:          ttl,
		Epoch:        epoch,
	}
	res, err := h.tokenIssuer.IssueToken(req, token.IssueOptions{}, domain.AuditContext{TraceID: "issue-token", Actor: subject})
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}
	return res.TokenString
}

func createGrant(t *testing.T, h *testHarness, subject string, action domain.Action, resource string) string {
	t.Helper()
	g, err := h.papSvc.CreateGrant(context.Background(), pap.CreateGrantRequest{
		Subject:  subject,
		Action:   action,
		Resource: resource,
	})
	if err != nil {
		t.Fatalf("failed to create grant: %v", err)
	}
	return g.ID
}

func Test10AcceptanceScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("TC-PEP-01: 정상 읽기", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "alice"
		resPath := "report.txt"
		content := []byte("hello world report")

		// 파일 사전 생성
		if err := os.WriteFile(filepath.Join(h.workspaceDir, resPath), content, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		tok := issueValidToken(t, h, sub, "file:read", 10*time.Minute, 1)
		createGrant(t, h, sub, domain.ActionFileRead, resPath)

		req := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileRead,
			Resource: resPath,
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute returned unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected Allowed=true, got false, reason=%s, details=%s", result.Reason, result.Details)
		}
		if result.ExitCode != domain.ExitSuccess {
			t.Errorf("expected ExitSuccess(0), got %d", result.ExitCode)
		}
		if result.Reason != domain.ReasonAuthorized {
			t.Errorf("expected ReasonAuthorized, got %s", result.Reason)
		}
		if string(result.Data) != string(content) {
			t.Errorf("expected data %s, got %s", content, result.Data)
		}
		if result.BytesRead != len(content) {
			t.Errorf("expected BytesRead %d, got %d", len(content), result.BytesRead)
		}
	})

	t.Run("TC-PEP-02: 정상 쓰기", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "bob"
		resPath := "logs/out.log"
		content := []byte("hello log")

		tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)
		createGrant(t, h, sub, domain.ActionFileWrite, resPath)

		req := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileWrite,
			Resource: resPath,
			Data:     content,
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if !result.Allowed || result.ExitCode != domain.ExitSuccess {
			t.Fatalf("expected write success, got allowed=%v, exit=%d, reason=%s", result.Allowed, result.ExitCode, result.Reason)
		}
		if result.BytesWrote != len(content) {
			t.Errorf("expected BytesWrote %d, got %d", len(content), result.BytesWrote)
		}

		// 실제 파일 디스크 기록 확인
		diskData, err := os.ReadFile(filepath.Join(h.workspaceDir, resPath))
		if err != nil {
			t.Fatalf("failed to read disk file: %v", err)
		}
		if string(diskData) != string(content) {
			t.Errorf("disk content mismatch: expected %s, got %s", content, diskData)
		}
	})

	t.Run("TC-PEP-03: Gate 1 거부 - 변조된 서명 토큰", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "eve"
		resPath := "confidential.txt"

		tokReq := token.IssueRequest{
			ClientID:     "client-orchestrator",
			ClientSecret: "orchestrator-secret-key-01",
			Subject:      sub,
			Audience:     "authz-harness",
			Scope:        "file:write",
			TTL:          10 * time.Minute,
			Epoch:        1,
		}
		res, err := h.tokenIssuer.IssueToken(tokReq, token.IssueOptions{TamperSignature: true}, domain.AuditContext{})
		if err != nil {
			t.Fatalf("issue error: %v", err)
		}

		req := pep.Request{
			Token:    res.TokenString,
			Action:   domain.ActionFileWrite,
			Resource: resPath,
			Data:     []byte("malicious write"),
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute returned error: %v", err)
		}

		if result.Allowed {
			t.Errorf("expected Allowed=false")
		}
		if result.ExitCode != domain.ExitTokenInvalid {
			t.Errorf("expected ExitTokenInvalid(11), got %d", result.ExitCode)
		}
		if result.Stage != pep.StageGate1AuthN {
			t.Errorf("expected StageGate1AuthN, got %s", result.Stage)
		}
		if result.Reason != domain.ReasonTokenInvalidSignature {
			t.Errorf("expected ReasonTokenInvalidSignature, got %s", result.Reason)
		}

		// 파일 부작용 0바이트 확인
		if _, err := os.Stat(filepath.Join(h.workspaceDir, resPath)); !os.IsNotExist(err) {
			t.Errorf("file should not exist on disk on Gate 1 denial")
		}
	})

	t.Run("TC-PEP-04: Gate 1 거부 - 만료된 토큰", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "alice"
		resPath := "expired.txt"

		tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)
		createGrant(t, h, sub, domain.ActionFileWrite, resPath)

		req := pep.Request{
			Token:       tok,
			Action:      domain.ActionFileWrite,
			Resource:    resPath,
			Data:        []byte("write data"),
			ClockOffset: 2 * time.Hour, // 2시간 경과 -> 만료
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if result.Allowed || result.ExitCode != domain.ExitTokenInvalid {
			t.Errorf("expected ExitTokenInvalid(11), got %d", result.ExitCode)
		}
		if result.Reason != domain.ReasonTokenExpired {
			t.Errorf("expected ReasonTokenExpired, got %s", result.Reason)
		}
	})

	t.Run("TC-PEP-05: Gate 1 거부 - 이미 소비된 jti Replay 재사용 토큰", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "alice"
		resPath := "file.txt"

		tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)
		createGrant(t, h, sub, domain.ActionFileWrite, resPath)

		req := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileWrite,
			Resource: resPath,
			Data:     []byte("first request"),
		}

		// 1회차 성공
		r1, err := h.gateway.Execute(ctx, req)
		if err != nil || !r1.Allowed {
			t.Fatalf("first request failed: %v", err)
		}

		// 2회차 Replay 시도 -> Gate 1 차단
		req2 := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileWrite,
			Resource: resPath,
			Data:     []byte("replay attack"),
		}
		r2, err := h.gateway.Execute(ctx, req2)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if r2.Allowed || r2.ExitCode != domain.ExitTokenInvalid {
			t.Errorf("expected ExitTokenInvalid(11), got %d", r2.ExitCode)
		}
		if r2.Reason != domain.ReasonTokenReplayDetected {
			t.Errorf("expected ReasonTokenReplayDetected, got %s", r2.Reason)
		}
	})

	t.Run("TC-PEP-06: Gate 2 거부 - Grant 미보유 리소스 접근", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "alice"
		unauthorizedRes := "confidential.txt"

		tok := issueValidToken(t, h, sub, "file:read", 10*time.Minute, 1)
		// Grant를 생성하지 않음

		req := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileRead,
			Resource: unauthorizedRes,
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if result.Allowed {
			t.Errorf("expected Allowed=false")
		}
		if result.ExitCode != domain.ExitAuthzDenied {
			t.Errorf("expected ExitAuthzDenied(12), got %d", result.ExitCode)
		}
		if result.Stage != pep.StageGate2AuthZ {
			t.Errorf("expected StageGate2AuthZ, got %s", result.Stage)
		}
		if result.Reason != domain.ReasonNoActiveGrant {
			t.Errorf("expected ReasonNoActiveGrant, got %s", result.Reason)
		}
	})

	t.Run("TC-PEP-07: Gate 2 거부 - 회수된(Revoked) Grant의 토큰 접근", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "alice"
		resPath := "revoked.txt"

		tok := issueValidToken(t, h, sub, "file:read", 10*time.Minute, 1)
		grantID := createGrant(t, h, sub, domain.ActionFileRead, resPath)

		// Grant 회수
		if _, err := h.papSvc.RevokeGrant(ctx, grantID); err != nil {
			t.Fatalf("failed to revoke grant: %v", err)
		}

		req := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileRead,
			Resource: resPath,
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if result.Allowed || result.ExitCode != domain.ExitAuthzDenied {
			t.Errorf("expected ExitAuthzDenied(12), got %d", result.ExitCode)
		}
		if result.Reason != domain.ReasonGrantRevoked {
			t.Errorf("expected ReasonGrantRevoked, got %s", result.Reason)
		}
	})

	t.Run("TC-PEP-08: Gate 2 거부 - Security Epoch 증가 후 구 Epoch 토큰 접근", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "alice"
		resPath := "epoch_test.txt"

		// Epoch 1 토큰 발급 및 Grant 생성
		tok := issueValidToken(t, h, sub, "file:read", 10*time.Minute, 1)
		createGrant(t, h, sub, domain.ActionFileRead, resPath)

		// Security Epoch 증가 (1 -> 2)
		newEpoch, err := h.papSvc.BumpEpoch(ctx, sub)
		if err != nil || newEpoch != 2 {
			t.Fatalf("failed to increment epoch: %v", err)
		}

		req := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileRead,
			Resource: resPath,
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if result.Allowed || result.ExitCode != domain.ExitAuthzDenied {
			t.Errorf("expected ExitAuthzDenied(12), got %d", result.ExitCode)
		}
		if result.Reason != domain.ReasonSubjectEpochRevoked {
			t.Errorf("expected ReasonSubjectEpochRevoked, got %s", result.Reason)
		}
	})

	t.Run("TC-PEP-09: Gate 2c 거부 - 상위 탈출 경로 순회 시도", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "attacker"
		// PDP용 인가 경로 (경로 순회 검증을 통과하는 형태)
		safeRes := "symlink_escape.txt"
		createGrant(t, h, sub, domain.ActionFileWrite, safeRes)

		// 실제 외부 디렉터리에 타겟 파일 생성 후 워크스페이스 내에 외부를 가리키는 심볼릭 링크 생성
		outsideDir := filepath.Join(t.TempDir(), "outside")
		_ = os.MkdirAll(outsideDir, 0755)
		outsideTarget := filepath.Join(outsideDir, "secret.txt")
		_ = os.WriteFile(outsideTarget, []byte("outside data"), 0644)

		symlinkPath := filepath.Join(h.workspaceDir, safeRes)
		if err := os.Symlink(outsideTarget, symlinkPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)

		req := pep.Request{
			Token:    tok,
			Action:   domain.ActionFileWrite,
			Resource: safeRes,
			Data:     []byte("root:x:0:0:evil"),
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if result.Allowed {
			t.Errorf("expected Allowed=false")
		}
		if result.ExitCode != domain.ExitPathViolation {
			t.Errorf("expected ExitPathViolation(13), got %d", result.ExitCode)
		}
		if result.Stage != pep.StageGate2cJail {
			t.Errorf("expected StageGate2cJail, got %s", result.Stage)
		}
		if result.Reason != domain.ReasonSymlinkEscape && result.Reason != domain.ReasonPathTraversal {
			t.Errorf("expected ReasonSymlinkEscape or ReasonPathTraversal, got %s", result.Reason)
		}
	})

	t.Run("TC-PEP-10: Stage 4 거부 - Fail-Closed 감사 실패 결함 주입 (Zero Side-Effects)", func(t *testing.T) {
		h := setupTestHarness(t)
		sub := "alice"
		targetFile := "audit_fail_test.txt"

		tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)
		createGrant(t, h, sub, domain.ActionFileWrite, targetFile)

		req := pep.Request{
			Token:              tok,
			Action:             domain.ActionFileWrite,
			Resource:           targetFile,
			Data:               []byte("secret data that must not be written"),
			InjectAuditFailure: true, // 결함 주입 스위치 활성화!
		}

		result, err := h.gateway.Execute(ctx, req)
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}

		if result.Allowed {
			t.Errorf("expected Allowed=false")
		}
		if result.ExitCode != domain.ExitAuditFailure {
			t.Errorf("expected ExitAuditFailure(15), got %d", result.ExitCode)
		}
		if result.Stage != pep.Stage4Audit {
			t.Errorf("expected Stage4Audit, got %s", result.Stage)
		}
		if result.Reason != domain.ReasonAuditLogFailed {
			t.Errorf("expected ReasonAuditLogFailed, got %s", result.Reason)
		}

		// **Fail-Closed 증명**: 디스크 파일이 일체 생성되지 않았음을 엄격히 검증
		targetDiskPath := filepath.Join(h.workspaceDir, targetFile)
		if _, err := os.Stat(targetDiskPath); !os.IsNotExist(err) {
			t.Fatalf("CRITICAL SECURITY INVARIANT VIOLATION: file %s exists on disk despite audit failure!", targetDiskPath)
		}
	})
}

func TestGate0InputValidation(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)

	testCases := []struct {
		name     string
		action   domain.Action
		resource string
	}{
		{"빈 리소스", domain.ActionFileRead, ""},
		{"공백 리소스", domain.ActionFileWrite, "   "},
		{"유효하지 않은 액션", domain.Action("delete"), "test.txt"},
		{"빈 액션", domain.Action(""), "test.txt"},
		{"net:fetch 는 040 전까지 거부", domain.ActionNetFetch, "127.0.0.1:18080"},
		{"exec:run 은 040 전까지 거부", domain.ActionExecRun, "echo-safe"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := h.gateway.Execute(ctx, pep.Request{
				Token:    "some.token.str",
				Action:   tc.action,
				Resource: tc.resource,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Allowed || res.ExitCode != domain.ExitBadInput {
				t.Errorf("expected ExitBadInput(14), got %d", res.ExitCode)
			}
			if res.Stage != pep.StageGate0Input {
				t.Errorf("expected StageGate0Input, got %s", res.Stage)
			}
			if res.Reason != domain.ReasonInvalidArguments {
				t.Errorf("expected ReasonInvalidArguments, got %s", res.Reason)
			}
		})
	}
}

func TestZeroLeakageAuditLog(t *testing.T) {
	// 감사 로그에 원시 Bearer 토큰 문자열이 전혀 기록되지 않는지 검증
	ctx := context.Background()
	h := setupTestHarness(t)
	sub := "zero-leak-user"
	resPath := "safe.txt"

	tok := issueValidToken(t, h, sub, "file:read", 10*time.Minute, 1)
	createGrant(t, h, sub, domain.ActionFileRead, resPath)

	_ = os.WriteFile(filepath.Join(h.workspaceDir, resPath), []byte("test"), 0644)

	res, err := h.gateway.Execute(ctx, pep.Request{
		Token:    tok,
		Action:   domain.ActionFileRead,
		Resource: resPath,
	})
	if err != nil || !res.Allowed {
		t.Fatalf("execute failed: %v", err)
	}

	auditBytes, err := os.ReadFile(h.auditFile)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	auditContent := string(auditBytes)

	// 서명된 JWT 원시 문자열 검증
	if strings.Contains(auditContent, tok) {
		t.Fatalf("ZERO LEAKAGE VIOLATION: raw bearer token leaked in audit.jsonl!")
	}
}

// TC-010-05: 기본 Audience 통일 검증 (IssueRequest{Audience: ""} -> pep.Execute(ExpectedAudience: "") 정상 통과)
func TestTC_010_05_DefaultAudience_Alignment(t *testing.T) {
	h := setupTestHarness(t)
	ctx := context.Background()

	// 파일 준비
	testFile := filepath.Join(h.workspaceDir, "default_aud.txt")
	if err := os.WriteFile(testFile, []byte("default aud content"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Grant 발급
	_, err := h.papSvc.CreateGrant(ctx, pap.CreateGrantRequest{
		Subject:  "worker-default-aud",
		Action:   domain.ActionFileRead,
		Resource: "default_aud.txt",
	})
	if err != nil {
		t.Fatalf("CreateGrant failed: %v", err)
	}

	// Audience 를 지정하지 않고 발급 (DefaultAudience="authz-harness" 적용)
	res, err := h.tokenIssuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-default-aud",
		Scope:        "file:read:default_aud.txt",
		Audience:     "", // 기본값 사용
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "tc-010-05-issue"})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// PEP 도 ExpectedAudience 없이 기본값으로 실행
	result, err := h.gateway.Execute(ctx, pep.Request{
		Token:            res.TokenString,
		Action:           domain.ActionFileRead,
		Resource:         "default_aud.txt",
		ExpectedAudience: "", // 기본값 사용
		TraceID:          "tc-010-05-exec",
	})
	if err != nil {
		t.Fatalf("PEP execute returned error: %v", err)
	}

	if !result.Allowed {
		t.Fatalf("expected allowed with default audience, got denied: reason=%s, details=%s",
			result.Reason, result.Details)
	}
	if result.Reason != domain.ReasonAuthorized {
		t.Fatalf("expected ReasonAuthorized, got %s", result.Reason)
	}
}

// TC-010-08: pep/gateway.go 내 문자열 에러 파싱 제거 검증 (Verifier 가 *domain.Error 반환 시 정확한 Reason 전달)
func TestTC_010_08_StructuredErrorReason_Extraction(t *testing.T) {
	h := setupTestHarness(t)
	ctx := context.Background()

	// 만료된 토큰으로 실행 (Gate 1 만료 에러 발생)
	res, err := h.tokenIssuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-expire",
		Scope:        "file:read:test.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "tc-010-08-issue"})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// ClockOffset 을 2시간 뒤로 설정하여 만료 유도
	result, err := h.gateway.Execute(ctx, pep.Request{
		Token:       res.TokenString,
		Action:      domain.ActionFileRead,
		Resource:    "test.txt",
		ClockOffset: 2 * time.Hour,
		TraceID:     "tc-010-08-exec",
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	if result.Allowed {
		t.Fatal("expected expired token to be denied, but got allowed")
	}
	if result.Reason != domain.ReasonTokenExpired {
		t.Fatalf("expected ReasonTokenExpired, got %s", result.Reason)
	}
	if result.ExitCode != domain.ExitTokenInvalid {
		t.Fatalf("expected ExitTokenInvalid (%d), got %d", domain.ExitTokenInvalid, result.ExitCode)
	}
}

// TC-030-08: PEP -> PDP 단일 TraceID 관통 검증
func TestTC_030_08_SingleTraceIDPropagation(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)
	sub := "worker-trace-01"
	resPath := "trace_test.txt"
	traceID := "trc-unified-777"

	tok := issueValidToken(t, h, sub, "file:read", 10*time.Minute, 1)
	createGrant(t, h, sub, domain.ActionFileRead, resPath)
	if err := os.WriteFile(filepath.Join(h.workspaceDir, resPath), []byte("hello trace"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	req := pep.Request{
		Token:    tok,
		Action:   domain.ActionFileRead,
		Resource: resPath,
		TraceID:  traceID,
	}

	result, err := h.gateway.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed, got denied with %s", result.Reason)
	}

	// audit.jsonl 파일에서 발생한 모든 이벤트의 trace_id 검증
	f, err := os.Open(h.auditFile)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer f.Close()

	var events []audit.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err == nil {
			// 이번 요청과 관련된 이벤트 필터링
			if ev.TraceID == traceID {
				events = append(events, ev)
			}
		}
	}

	if len(events) < 3 {
		t.Fatalf("expected at least 3 events for trace %s (authn.verify, pdp.decide, pep.allow), got %d", traceID, len(events))
	}

	for _, ev := range events {
		if ev.TraceID != traceID {
			t.Errorf("expected traceID %s, got %s", traceID, ev.TraceID)
		}
		if ev.Decision == "" {
			t.Errorf("event missing top-level decision: %+v", ev)
		}
	}
}

// TC-030-09: PEP 거부 시 표준 Action 기록 (pep.deny, decision: deny)
func TestTC_030_09_PepDenyStandardAction(t *testing.T) {
	ctx := context.Background()
	h := setupTestHarness(t)
	sub := "worker-deny-01"
	resPath := "unauthorized.txt"
	traceID := "trc-deny-888"

	tok := issueValidToken(t, h, sub, "file:write", 10*time.Minute, 1)
	// Grant를 생성하지 않고 접근 시도 -> 거부 유도

	req := pep.Request{
		Token:    tok,
		Action:   domain.ActionFileWrite,
		Resource: resPath,
		TraceID:  traceID,
	}

	result, err := h.gateway.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if result.Allowed {
		t.Fatalf("expected denied, got allowed")
	}

	f, err := os.Open(h.auditFile)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer f.Close()

	var lastEv audit.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err == nil && ev.TraceID == traceID {
			lastEv = ev
		}
	}

	if lastEv.Action != "pep.deny" {
		t.Errorf("expected final action 'pep.deny', got %q", lastEv.Action)
	}
	if lastEv.Decision != "deny" {
		t.Errorf("expected decision 'deny', got %q", lastEv.Decision)
	}
	if lastEv.Reason != string(domain.ReasonNoActiveGrant) {
		t.Errorf("expected reason %s, got %s", domain.ReasonNoActiveGrant, lastEv.Reason)
	}
}

// --- Track B: 인메모리 Stub 기반 순수 배선 독립 테스트 스위트 ---

type stubVerifier struct {
	claimsToReturn *domain.VerifiedClaims
	errToReturn    error
	calls          int
	lastOpts       token.VerifyOptions
	lastAuditCtx   domain.AuditContext
	consumeCalls   int
	consumeErr     error
}

func (s *stubVerifier) VerifyToken(tokenStr string, opts token.VerifyOptions, actx domain.AuditContext) (*domain.VerifiedClaims, error) {
	s.calls++
	s.lastOpts = opts
	s.lastAuditCtx = actx
	if s.errToReturn != nil {
		return nil, s.errToReturn
	}
	return s.claimsToReturn, nil
}

func (s *stubVerifier) ConsumeReplay(claims domain.TokenClaims, actx domain.AuditContext) error {
	s.consumeCalls++
	return s.consumeErr
}

func (s *stubVerifier) InspectToken(tokenStr string) (*token.JWTHeader, *domain.TokenClaims, error) {
	return nil, nil, nil
}

type stubPDP struct {
	decisionToReturn *pdp.Decision
	errToReturn      error
	calls            int
	lastReq          pdp.Request
}

func (s *stubPDP) Decide(ctx context.Context, req pdp.Request) (*pdp.Decision, error) {
	s.calls++
	s.lastReq = req
	if s.errToReturn != nil {
		return nil, s.errToReturn
	}
	return s.decisionToReturn, nil
}

type stubJail struct {
	files        map[string][]byte
	resolveErr   error
	readErr      error
	writeErr     error
	callsRead    int
	callsWrite   int
	lastResolved string
}

func (s *stubJail) ResolvePath(rawPath string, forWrite bool) (string, error) {
	if s.resolveErr != nil {
		return "", s.resolveErr
	}
	s.lastResolved = "/safe/workspace/" + rawPath
	return s.lastResolved, nil
}

func (s *stubJail) ReadFile(rawPath string) ([]byte, error) {
	s.callsRead++
	if s.readErr != nil {
		return nil, s.readErr
	}
	if s.files != nil {
		if data, ok := s.files[rawPath]; ok {
			return data, nil
		}
	}
	return []byte("stub file content"), nil
}

func (s *stubJail) WriteFile(rawPath string, data []byte) error {
	s.callsWrite++
	if s.writeErr != nil {
		return s.writeErr
	}
	if s.files == nil {
		s.files = make(map[string][]byte)
	}
	s.files[rawPath] = data
	return nil
}

func (s *stubJail) WorkspaceRoot() string {
	return "/safe/workspace"
}

type stubAuditWriter struct {
	events      []audit.Event
	errToReturn error
}

func (s *stubAuditWriter) Log(e audit.Event) error {
	if s.errToReturn != nil {
		return s.errToReturn
	}
	s.events = append(s.events, e)
	return nil
}

func (s *stubAuditWriter) Close() error {
	return nil
}

// TestTrackB_WiringPipeline_Isolated 는 TC-060-05 불변식에 따라
// 디스크 I/O 없이 메모리 Stub(Verifier, PDP, Jail, Audit)만을 사용하여
// 단일 TraceID 관통, 관문 단락(Short-Circuit), Pre-Commit Fail-Closed, 데코레이터 배선만을
// 100% 독립적으로 검증한다 (Track B).
func TestTrackB_WiringPipeline_Isolated(t *testing.T) {
	ctx := context.Background()

	t.Run("TC-060-05-1: 단일 TraceID 관통 및 스탬핑 배선 검증", func(t *testing.T) {
		traceID := "trc-trackB-001"
		verifier := &stubVerifier{
			claimsToReturn: &domain.VerifiedClaims{
				Claims: domain.TokenClaims{
					Subject: "worker-01",
					JWTID:   "jti-001",
					Scope:   "file:read",
					Epoch:   1,
				},
			},
		}
		pdpStub := &stubPDP{
			decisionToReturn: &pdp.Decision{
				Decision: pdp.DecisionAllow,
				Reason:   domain.ReasonAuthorized,
				GrantID:  "grant-001",
			},
		}
		jailStub := &stubJail{}
		auditStub := &stubAuditWriter{}

		gw, err := pep.NewGateway(pep.Config{
			Verifier:    verifier,
			PDP:         pdpStub,
			Jail:        jailStub,
			AuditWriter: auditStub,
		})
		if err != nil {
			t.Fatalf("failed to create gateway: %v", err)
		}

		req := pep.Request{
			Token:    "valid.mock.token",
			Action:   domain.ActionFileRead,
			Resource: "docs/spec.txt",
			TraceID:  traceID,
		}

		res, err := gw.Execute(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("expected allowed, got denied: %s", res.Reason)
		}

		// Verifier 에 전달된 AuditContext의 TraceID 확인
		if verifier.lastAuditCtx.TraceID != traceID {
			t.Errorf("verifier received wrong traceID: %s", verifier.lastAuditCtx.TraceID)
		}
		// PDP 에 전달된 Request의 TraceID 확인
		if pdpStub.lastReq.TraceID != traceID {
			t.Errorf("pdp received wrong traceID: %s", pdpStub.lastReq.TraceID)
		}
		// 감사 이벤트들의 TraceID 확인
		if len(auditStub.events) == 0 {
			t.Fatal("expected audit events to be recorded")
		}
		for _, ev := range auditStub.events {
			if ev.TraceID != traceID {
				t.Errorf("audit event traceID mismatch: expected %s, got %s", traceID, ev.TraceID)
			}
		}
	})

	t.Run("TC-060-05-2: Gate 1 AuthN 실패 시 PDP/Jail 단락(Short-Circuit) 배선 검증", func(t *testing.T) {
		verifier := &stubVerifier{
			errToReturn: domain.NewError(domain.ReasonTokenInvalidSignature, "verify", "bad sig", token.ErrInvalidSignature),
		}
		pdpStub := &stubPDP{}
		jailStub := &stubJail{}
		auditStub := &stubAuditWriter{}

		gw, err := pep.NewGateway(pep.Config{
			Verifier:    verifier,
			PDP:         pdpStub,
			Jail:        jailStub,
			AuditWriter: auditStub,
		})
		if err != nil {
			t.Fatalf("failed to create gateway: %v", err)
		}

		req := pep.Request{
			Token:    "bad.signature.token",
			Action:   domain.ActionFileRead,
			Resource: "docs/spec.txt",
			TraceID:  "trc-short-authn",
		}

		res, err := gw.Execute(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatal("expected denied on authn error, got allowed")
		}
		if res.Stage != pep.StageGate1AuthN {
			t.Errorf("expected StageGate1AuthN, got %s", res.Stage)
		}
		if pdpStub.calls != 0 {
			t.Errorf("expected 0 calls to PDP on authn failure, got %d", pdpStub.calls)
		}
		if jailStub.callsRead != 0 || jailStub.callsWrite != 0 {
			t.Errorf("expected 0 calls to Jail on authn failure, got read=%d write=%d", jailStub.callsRead, jailStub.callsWrite)
		}
	})

	t.Run("TC-060-05-3: Gate 2 PDP Deny 시 Jail 단락(Short-Circuit) 배선 검증", func(t *testing.T) {
		verifier := &stubVerifier{
			claimsToReturn: &domain.VerifiedClaims{
				Claims: domain.TokenClaims{
					Subject: "worker-01",
					JWTID:   "jti-002",
					Scope:   "file:read",
					Epoch:   1,
				},
			},
		}
		pdpStub := &stubPDP{
			decisionToReturn: &pdp.Decision{
				Decision: pdp.DecisionDeny,
				Reason:   domain.ReasonNoActiveGrant,
			},
		}
		jailStub := &stubJail{}
		auditStub := &stubAuditWriter{}

		gw, err := pep.NewGateway(pep.Config{
			Verifier:    verifier,
			PDP:         pdpStub,
			Jail:        jailStub,
			AuditWriter: auditStub,
		})
		if err != nil {
			t.Fatalf("failed to create gateway: %v", err)
		}

		req := pep.Request{
			Token:    "valid.token",
			Action:   domain.ActionFileRead,
			Resource: "unauthorized.txt",
			TraceID:  "trc-short-pdp",
		}

		res, err := gw.Execute(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatal("expected denied on pdp deny, got allowed")
		}
		if res.Stage != pep.StageGate2AuthZ {
			t.Errorf("expected StageGate2AuthZ, got %s", res.Stage)
		}
		if jailStub.callsRead != 0 || jailStub.callsWrite != 0 {
			t.Errorf("expected 0 calls to Jail on pdp deny, got read=%d write=%d", jailStub.callsRead, jailStub.callsWrite)
		}
	})

	t.Run("TC-060-05-4: Pre-Commit 감사 실패 시 Fail-Closed 배선 검증", func(t *testing.T) {
		verifier := &stubVerifier{
			claimsToReturn: &domain.VerifiedClaims{
				Claims: domain.TokenClaims{
					Subject: "worker-01",
					JWTID:   "jti-003",
					Scope:   "file:write",
					Epoch:   1,
				},
			},
		}
		pdpStub := &stubPDP{
			decisionToReturn: &pdp.Decision{
				Decision: pdp.DecisionAllow,
				Reason:   domain.ReasonAuthorized,
				GrantID:  "grant-003",
			},
		}
		jailStub := &stubJail{}
		auditStub := &stubAuditWriter{
			errToReturn: fmt.Errorf("simulated audit disk full error"),
		}

		gw, err := pep.NewGateway(pep.Config{
			Verifier:    verifier,
			PDP:         pdpStub,
			Jail:        jailStub,
			AuditWriter: auditStub,
		})
		if err != nil {
			t.Fatalf("failed to create gateway: %v", err)
		}

		req := pep.Request{
			Token:    "valid.token",
			Action:   domain.ActionFileWrite,
			Resource: "data.txt",
			Data:     []byte("fail closed test"),
			TraceID:  "trc-audit-fail",
		}

		res, err := gw.Execute(ctx, req)
		if err != nil {
			t.Fatalf("unexpected execution error: %v", err)
		}
		if res == nil {
			t.Fatal("expected non-nil result on pre-commit audit failure")
		}
		if res.Allowed {
			t.Fatal("expected denied on pre-commit audit failure, got allowed")
		}
		if res.ExitCode != domain.ExitAuditFailure {
			t.Errorf("expected ExitAuditFailure (%d), got %d", domain.ExitAuditFailure, res.ExitCode)
		}
		if res.Reason != domain.ReasonAuditLogFailed {
			t.Errorf("expected ReasonAuditLogFailed, got %s", res.Reason)
		}
		// 핵심: 감사 기록 실패 시 파일 쓰기가 절대로 실행되지 않아야 함 (디스크 부작용 0)
		if jailStub.callsWrite != 0 {
			t.Fatalf("violation of Fail-Closed: Jail.WriteFile was called %d times despite audit failure", jailStub.callsWrite)
		}
	})

	t.Run("TC-060-05-5: WithBeforeIOHook 데코레이터 정상 배선 검증", func(t *testing.T) {
		verifier := &stubVerifier{
			claimsToReturn: &domain.VerifiedClaims{
				Claims: domain.TokenClaims{
					Subject: "worker-01",
					JWTID:   "jti-004",
					Scope:   "file:write",
					Epoch:   1,
				},
			},
		}
		pdpStub := &stubPDP{
			decisionToReturn: &pdp.Decision{
				Decision: pdp.DecisionAllow,
				Reason:   domain.ReasonAuthorized,
				GrantID:  "grant-004",
			},
		}
		jailStub := &stubJail{}
		auditStub := &stubAuditWriter{}

		gw, err := pep.NewGateway(pep.Config{
			Verifier:    verifier,
			PDP:         pdpStub,
			Jail:        jailStub,
			AuditWriter: auditStub,
		})
		if err != nil {
			t.Fatalf("failed to create gateway: %v", err)
		}

		hookCalled := false
		hookAction := ""
		hookResource := ""

		hook := func(ctx context.Context, r pep.Request) error {
			hookCalled = true
			hookAction = string(r.Action)
			hookResource = r.Resource
			return nil
		}

		decoratedGW := pep.WithBeforeIOHook(gw, hook)

		req := pep.Request{
			Token:                "valid.token",
			Action:               domain.ActionFileWrite,
			Resource:             "hook_test.txt",
			Data:                 []byte("hook test data"),
			TraceID:              "trc-hook-001",
			InjectRevokeBeforeIO: true,
		}

		res, err := decoratedGW.Execute(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("expected allowed, got denied: %s", res.Reason)
		}
		if !hookCalled {
			t.Fatal("expected WithBeforeIOHook to be called before I/O, but was not called")
		}
		if hookAction != string(domain.ActionFileWrite) || hookResource != "hook_test.txt" {
			t.Errorf("hook received unexpected args: action=%s resource=%s", hookAction, hookResource)
		}
		if jailStub.callsWrite != 1 {
			t.Errorf("expected Jail.WriteFile to be called 1 time, got %d", jailStub.callsWrite)
		}
	})

	t.Run("TC-060-05-6: SESE 단일 입출구, slog Around 계측 및 AgentID/CallerID 위임 계보 스탬핑 검증", func(t *testing.T) {
		var logBuf strings.Builder
		testLogger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))

		actorClaim := &domain.ActorClaim{
			Subject: "orchestrator-main",
		}
		verifier := &stubVerifier{
			claimsToReturn: &domain.VerifiedClaims{
				Claims: domain.TokenClaims{
					Subject: "worker-child-01",
					JWTID:   "jti-child-888",
					Scope:   "file:read",
					Epoch:   1,
					Actor:   actorClaim,
				},
			},
		}
		pdpStub := &stubPDP{
			decisionToReturn: &pdp.Decision{
				Decision: pdp.DecisionAllow,
				Reason:   domain.ReasonAuthorized,
				GrantID:  "grant-child-01",
			},
		}
		jailStub := &stubJail{
			files: map[string][]byte{
				"delegated.txt": []byte("delegated content"),
			},
		}
		auditStub := &stubAuditWriter{}

		gw, err := pep.NewGateway(pep.Config{
			Verifier:    verifier,
			PDP:         pdpStub,
			Jail:        jailStub,
			AuditWriter: auditStub,
			Observer:    slogadapter.New(testLogger),
		})
		if err != nil {
			t.Fatalf("failed to create gateway: %v", err)
		}

		req := pep.Request{
			Token:    "valid.delegated.token",
			Action:   domain.ActionFileRead,
			Resource: "delegated.txt",
			TraceID:  "trc-delegation-sese-001",
		}

		res, err := gw.Execute(ctx, req)
		if err != nil {
			t.Fatalf("unexpected execution error: %v", err)
		}
		if !res.Allowed || res.ExitCode != domain.ExitSuccess {
			t.Fatalf("expected allowed with ExitSuccess, got: allowed=%v exit=%d", res.Allowed, res.ExitCode)
		}
		if string(res.Data) != "delegated content" {
			t.Errorf("unexpected read content: %s", string(res.Data))
		}

		// 1. slog Around 로깅 검증: entering, passed, finished
		logs := logBuf.String()
		if !strings.Contains(logs, "pep stage entering") {
			t.Errorf("slog output missing 'pep stage entering'")
		}
		if !strings.Contains(logs, "pep stage passed") {
			t.Errorf("slog output missing 'pep stage passed'")
		}
		if !strings.Contains(logs, "pep execution succeeded") {
			t.Errorf("slog output missing 'pep execution succeeded'")
		}
		if strings.Contains(logs, "valid.delegated.token") {
			t.Errorf("Zero Leakage violation: raw token leaked in slog logs")
		}

		// 2. audit.Event의 AgentID 및 CallerID 스탬핑 검증
		if len(auditStub.events) < 2 {
			t.Fatalf("expected at least 2 audit events (pre-commit + completed), got %d", len(auditStub.events))
		}
		preCommitEv := auditStub.events[0]
		completedEv := auditStub.events[len(auditStub.events)-1]

		for i, ev := range []audit.Event{preCommitEv, completedEv} {
			if ev.AgentID != "worker-child-01" {
				t.Errorf("event %d: expected AgentID 'worker-child-01', got %q", i, ev.AgentID)
			}
			callerID, ok := ev.Metadata["caller_id"].(string)
			if !ok || callerID != "orchestrator-main" {
				t.Errorf("event %d: expected Metadata['caller_id'] to be 'orchestrator-main', got %v", i, ev.Metadata["caller_id"])
			}
		}
	})
}
