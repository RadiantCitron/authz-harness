package pep_test

import (
	"bufio"
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
