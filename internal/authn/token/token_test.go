package token

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/domain"
)

type testRig struct {
	keyMgr       keys.KeyManager
	clients      *InMemoryClientRegistry
	replayLedger ReplayLedger
	issuer       *Service
	verifier     *Verifier
	auditPath    string
}

func setupTestRig(t *testing.T) *testRig {
	t.Helper()
	tmpDir := t.TempDir()

	privPath := filepath.Join(tmpDir, "signing_keys.priv.json")
	pubPath := filepath.Join(tmpDir, "jwks.pub.json")
	replayPath := filepath.Join(tmpDir, "replay_ledger.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	store, err := keys.NewFileStore(privPath, pubPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("failed to create audit writer: %v", err)
	}

	keyMgr, err := keys.NewManager(store, auditWriter)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	// 초기 활성 키 생성
	_, err = keyMgr.RotateKey(domain.AuditContext{TraceID: "init-trace", Actor: "test"})
	if err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}

	clients := NewInMemoryClientRegistry()
	replayLedger, err := NewFileReplayLedger(replayPath, domain.RealClock{})
	if err != nil {
		t.Fatalf("failed to create replay ledger: %v", err)
	}

	clock := domain.RealClock{}
	issuer := NewService(keyMgr, clients, auditWriter, clock)
	verifier := NewVerifier(keyMgr, replayLedger, auditWriter, clock)

	return &testRig{
		keyMgr:       keyMgr,
		clients:      clients,
		replayLedger: replayLedger,
		issuer:       issuer,
		verifier:     verifier,
		auditPath:    auditPath,
	}
}

// 시나리오 1: 정상 토큰 발급 및 authn 단계 통과
func TestScenario1_ValidTokenPass(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
		Scope:        "file:read:docs/plan.txt",
		Audience:     "authz-service",
		TTL:          time.Hour,
		Epoch:        1,
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{}, domain.AuditContext{TraceID: "t1", Actor: "client-orchestrator"})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// Inspect 검증
	header, claims, err := rig.verifier.InspectToken(res.TokenString)
	if err != nil {
		t.Fatalf("InspectToken failed: %v", err)
	}
	if header.Type != "at+jwt" || header.Algorithm != "EdDSA" {
		t.Fatalf("unexpected header: %+v", header)
	}
	if claims.Subject != "worker-01" || claims.Scope != "file:read:docs/plan.txt" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Verify 검증
	verified, err := rig.verifier.VerifyToken(res.TokenString, VerifyOptions{
		ExpectedAudience: "authz-service",
		ExpectedSubject:  "worker-01",
	}, domain.AuditContext{TraceID: "t1-v", Actor: "verifier"})
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if verified.Claims.JWTID != res.Claims.JWTID {
		t.Fatalf("jti mismatch: expected %s, got %s", res.Claims.JWTID, verified.Claims.JWTID)
	}
}

// 시나리오 2: alg: none 차단
func TestScenario2_AlgNoneBlocked(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
		Scope:        "file:read:docs/plan.txt",
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{TamperAlgNone: true}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	_, err = rig.verifier.VerifyToken(res.TokenString, VerifyOptions{}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected alg: none to be blocked, but got pass")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenAlgNotAllowed {
		t.Fatalf("expected reason %s, got %v", domain.ReasonTokenAlgNotAllowed, err)
	}
}

// 시나리오 3: typ != at+jwt 차단
func TestScenario3_InvalidTypBlocked(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{TamperTyp: "JWT"}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	_, err = rig.verifier.VerifyToken(res.TokenString, VerifyOptions{}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected invalid typ to be blocked, but got pass")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenInvalidType {
		t.Fatalf("expected reason %s, got %v", domain.ReasonTokenInvalidType, err)
	}
}

// 시나리오 4: 서명 변조 차단
func TestScenario4_TamperedSignatureBlocked(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{TamperSignature: true}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	_, err = rig.verifier.VerifyToken(res.TokenString, VerifyOptions{}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected tampered signature to be blocked, but got pass")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenInvalidSignature {
		t.Fatalf("expected reason %s, got %v", domain.ReasonTokenInvalidSignature, err)
	}
}

// 시나리오 5: 시간 유효성 (만료) 차단
func TestScenario5_ExpiredTokenBlocked(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
		TTL:          1 * time.Hour,
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// 2시간 뒤 시계로 검증
	_, err = rig.verifier.VerifyToken(res.TokenString, VerifyOptions{ClockOffset: 2 * time.Hour}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected expired token to be blocked, but got pass")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenExpired {
		t.Fatalf("expected reason %s, got %v", domain.ReasonTokenExpired, err)
	}
}

// 시나리오 6: Replay 원장 중복 소비 차단
func TestScenario6_ReplayBlocked(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// 1회차: 정상 Pass
	_, err = rig.verifier.VerifyToken(res.TokenString, VerifyOptions{RecordReplay: true}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("first verification failed: %v", err)
	}

	// 2회차: Replay 차단
	_, err = rig.verifier.VerifyToken(res.TokenString, VerifyOptions{RecordReplay: true}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected replayed token to be blocked, but got pass")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenReplayDetected {
		t.Fatalf("expected reason %s, got %v", domain.ReasonTokenReplayDetected, err)
	}
}

// 시나리오 7: 키 폐기(Revoke) 즉시 무효화 연동
func TestScenario7_KeyRevokedBlocked(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// 키 폐기 실행
	err = rig.keyMgr.RevokeKey(res.KeyID, domain.AuditContext{TraceID: "revoke-t", Actor: "admin"})
	if err != nil {
		t.Fatalf("RevokeKey failed: %v", err)
	}

	// 폐기된 키로 발급된 토큰 검증 시 차단
	_, err = rig.verifier.VerifyToken(res.TokenString, VerifyOptions{}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected revoked key token to be blocked, but got pass")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenKeyRetired {
		t.Fatalf("expected reason %s, got %v", domain.ReasonTokenKeyRetired, err)
	}
}

// 시나리오 8: 미등록 / 잘못된 시크릿 클라이언트 인증 차단
func TestScenario8_ClientAuthFail(t *testing.T) {
	rig := setupTestRig(t)

	// 8-1. 미등록 클라이언트
	_, err := rig.issuer.IssueToken(IssueRequest{
		ClientID:     "unknown-client",
		ClientSecret: "any-pass",
		Subject:      "worker-01",
	}, IssueOptions{}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected unknown client to fail")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonAuthnUnknownClient {
		t.Fatalf("expected reason %s, got %v", domain.ReasonAuthnUnknownClient, err)
	}

	// 8-2. 시크릿 불일치
	_, err = rig.issuer.IssueToken(IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "wrong-secret-000",
		Subject:      "worker-01",
	}, IssueOptions{}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected wrong secret to fail")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonAuthnInvalidSecret {
		t.Fatalf("expected reason %s, got %v", domain.ReasonAuthnInvalidSecret, err)
	}
}

// 동시성 테스트: Replay 원장 동시 소비 경합
func TestConcurrentReplay(t *testing.T) {
	rig := setupTestRig(t)

	req := IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "worker-01",
	}

	res, err := rig.issuer.IssueToken(req, IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	concurrency := 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	passCount := 0
	failCount := 0
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			_, err := rig.verifier.VerifyToken(res.TokenString, VerifyOptions{RecordReplay: true}, domain.AuditContext{})
			mu.Lock()
			if err == nil {
				passCount++
			} else {
				failCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	if passCount != 1 {
		t.Fatalf("expected exactly 1 pass, got %d (fail %d)", passCount, failCount)
	}
	if failCount != concurrency-1 {
		t.Fatalf("expected %d fails, got %d", concurrency-1, failCount)
	}
}

// Fuzzing 테스트: 비정상 토큰 스트림 파싱 패닉 방어
func FuzzTokenParser(f *testing.F) {
	f.Add("eyJhbGciOiJFZERTQTEifQ.eyJzdWIiOiIxIn0.c2ln")
	f.Add("..")
	f.Add("a.b")
	f.Add("a.b.c.d")
	f.Add("")

	rig := setupTestRig(&testing.T{})

	f.Fuzz(func(t *testing.T, token string) {
		_, _, _ = rig.verifier.InspectToken(token)
		_, _ = rig.verifier.VerifyToken(token, VerifyOptions{}, domain.AuditContext{})
	})
}
