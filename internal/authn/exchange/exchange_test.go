package exchange_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

type mutableClock struct {
	mu sync.RWMutex
	t  time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.t
}

func (c *mutableClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func setupTestHarness(t *testing.T, now time.Time) (*exchange.ExchangeService, *token.Service, *token.Verifier, keys.KeyManager, audit.Writer, string, *mutableClock) {
	t.Helper()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "signing_keys.priv.json")
	pubPath := filepath.Join(dir, "jwks.pub.json")
	replayPath := filepath.Join(dir, "replay_ledger.json")
	auditPath := filepath.Join(dir, "audit.jsonl")

	st, err := keys.NewFileStore(privPath, pubPath)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("NewJSONLWriter failed: %v", err)
	}

	keyMgr, err := keys.NewManager(st, auditWriter)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Active 키 1개 생성
	_, err = keyMgr.RotateKey(domain.AuditContext{TraceID: "setup", Actor: "test"})
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	clk := &mutableClock{t: now}
	replayLedger, err := token.NewFileReplayLedger(replayPath, clk)
	if err != nil {
		t.Fatalf("NewFileReplayLedger failed: %v", err)
	}

	clients := token.NewInMemoryClientRegistry()
	issuer := token.NewService(keyMgr, clients, auditWriter, clk)
	verifier := token.NewVerifier(keyMgr, replayLedger, auditWriter, clk)
	validator := exchange.NewDownscopeValidator()

	svc, err := exchange.NewExchangeService(issuer, verifier, clients, validator, auditWriter, clk)
	if err != nil {
		t.Fatalf("NewExchangeService failed: %v", err)
	}

	return svc, issuer, verifier, keyMgr, auditWriter, auditPath, clk
}

// 1. 정상 축소 위임 및 act 클레임 생성
func TestExchange_Success_SingleDelegation(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, verifier, _, _, _, _ := setupTestHarness(t, baseTime)

	// 부모 토큰 발급: orchestrator, scope 2개, 1시간 TTL
	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt file:write:docs/out.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	// 교환 요청: worker-01 에게 1개 스코프만 축소 위임, TTL 30분
	res, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          30 * time.Minute,
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	if res.ParentJTI != parentRes.Claims.JWTID {
		t.Errorf("expected parent JTI %s, got %s", parentRes.Claims.JWTID, res.ParentJTI)
	}
	if res.DelegationDepth != 1 {
		t.Errorf("expected delegation depth 1, got %d", res.DelegationDepth)
	}
	if res.Claims.Subject != "worker-01" {
		t.Errorf("expected subject worker-01, got %s", res.Claims.Subject)
	}
	if res.Claims.Scope != "file:read:docs/plan.txt" {
		t.Errorf("expected scope file:read:docs/plan.txt, got %s", res.Claims.Scope)
	}
	if res.Claims.Actor == nil {
		t.Fatalf("expected non-nil act claim")
	}
	if res.Claims.Actor.Subject != "orchestrator-main" {
		t.Errorf("expected actor subject orchestrator-main, got %s", res.Claims.Actor.Subject)
	}
	if res.Claims.Actor.JWTID != parentRes.Claims.JWTID {
		t.Errorf("expected actor jti %s, got %s", parentRes.Claims.JWTID, res.Claims.Actor.JWTID)
	}

	// 자식 토큰 authn 단계 검증
	verified, err := verifier.VerifyToken(res.TokenString, token.VerifyOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("child token verify failed: %v", err)
	}
	if verified.Claims.Subject != "worker-01" {
		t.Errorf("expected verified subject worker-01, got %s", verified.Claims.Subject)
	}
}

// 2. 부모 Scope 초과 요청 차단 (DELEGATION_SCOPE_EXCEEDED)
func TestExchange_Deny_ScopeExceeded(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt file:write:docs/secret.txt",
		TTL:          30 * time.Minute,
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected scope exceeded error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonDelegationScopeExceeded {
		t.Errorf("expected reason %s in error: %v", domain.ReasonDelegationScopeExceeded, err)
	}
}

// 3. 부모 잔여 TTL 초과 요청 차단 (DELEGATION_TTL_EXCEEDED)
func TestExchange_Deny_TTLExceeded(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          10 * time.Minute,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          30 * time.Minute, // 10분 초과
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected ttl exceeded error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonDelegationTTLExceeded {
		t.Errorf("expected reason %s in error: %v", domain.ReasonDelegationTTLExceeded, err)
	}
}

// 4. 변조된 부모 토큰 제출 시 교환 차단
func TestExchange_Deny_TamperedParentToken(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{
		TamperSignature: true, // 변조된 서명
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          30 * time.Minute,
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected signature verification error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenInvalidSignature {
		t.Errorf("expected reason %s in error: %v", domain.ReasonTokenInvalidSignature, err)
	}
}

// 5. 만료된 부모 토큰 제출 시 교환 차단
func TestExchange_Deny_ExpiredParentToken(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, clk := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          10 * time.Minute,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	// 15분 후로 클럭 전진 (부모 토큰 10분 만료 경과)
	clk.Set(baseTime.Add(15 * time.Minute))

	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          5 * time.Minute,
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected expired token error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenExpired {
		t.Errorf("expected reason %s in error: %v", domain.ReasonTokenExpired, err)
	}
}

// 6. 서명 키 폐기된 부모 토큰 제출 시 교환 차단
func TestExchange_Deny_RevokedParentKey(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, keyMgr, _, _, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	// 부모 토큰 서명 키 폐기 (revoke)
	err = keyMgr.RevokeKey(parentRes.KeyID, domain.AuditContext{TraceID: "revoke-test", Actor: "admin"})
	if err != nil {
		t.Fatalf("RevokeKey failed: %v", err)
	}

	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          30 * time.Minute,
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected retired key error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenKeyRetired {
		t.Errorf("expected reason %s in error: %v", domain.ReasonTokenKeyRetired, err)
	}
}

// 7. 다단계 위임 및 최대 깊이 초과 차단 (MaxDelegationDepth = 3)
func TestExchange_Deny_MaxDepthExceeded(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, _ := setupTestHarness(t, baseTime)

	// 부모 (Depth 0)
	t0, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          2 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken depth 0 failed: %v", err)
	}

	// Depth 1 (worker-01)
	t1, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  t0.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          90 * time.Minute,
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("Exchange depth 1 failed: %v", err)
	}
	if t1.DelegationDepth != 1 {
		t.Fatalf("expected depth 1, got %d", t1.DelegationDepth)
	}

	// Depth 2 (worker-02)
	t2, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  t1.TokenString,
		ChildSubject: "worker-02",
		Scope:        "file:read:docs/plan.txt",
		TTL:          80 * time.Minute,
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("Exchange depth 2 failed: %v", err)
	}
	if t2.DelegationDepth != 2 {
		t.Fatalf("expected depth 2, got %d", t2.DelegationDepth)
	}

	// Depth 3 (worker-03)
	t3, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  t2.TokenString,
		ChildSubject: "worker-03",
		Scope:        "file:read:docs/plan.txt",
		TTL:          70 * time.Minute,
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("Exchange depth 3 failed: %v", err)
	}
	if t3.DelegationDepth != 3 {
		t.Fatalf("expected depth 3, got %d", t3.DelegationDepth)
	}

	// Depth 4 시도 (worker-04) -> 차단되어야 함
	// worker-04를 위해 client-orchestrator 사용 (allowedSubs: *)
	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		ParentToken:  t3.TokenString,
		ChildSubject: "worker-04",
		Scope:        "file:read:docs/plan.txt",
		TTL:          60 * time.Minute,
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected max depth exceeded error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonDelegationDepthExceeded {
		t.Errorf("expected reason %s in error: %v", domain.ReasonDelegationDepthExceeded, err)
	}
}

// 8. 동일 주체 순환 위임 차단 (DELEGATION_SELF_LOOP)
func TestExchange_Deny_SelfLoop(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		Subject:      "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	// 1) 직전 부모와 동일한 경우
	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01", // self loop
		Scope:        "file:read:docs/plan.txt",
		TTL:          30 * time.Minute,
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected self loop error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonDelegationSelfLoop {
		t.Errorf("expected reason %s in error: %v", domain.ReasonDelegationSelfLoop, err)
	}

	// 2) Depth 1 -> 2 에서 최초 부모(orchestrator-main)로 다시 위임하는 순환 시도
	p0, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken p0 failed: %v", err)
	}

	p1, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  p0.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          40 * time.Minute,
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("Exchange p1 failed: %v", err)
	}

	// p1 으로 다시 orchestrator-main 을 자식으로 지정
	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		ParentToken:  p1.TokenString,
		ChildSubject: "orchestrator-main", // loop in actor chain
		Scope:        "file:read:docs/plan.txt",
		TTL:          30 * time.Minute,
	}, domain.AuditContext{})

	if err == nil {
		t.Fatal("expected actor chain self loop error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonDelegationSelfLoop {
		t.Errorf("expected reason %s in error: %v", domain.ReasonDelegationSelfLoop, err)
	}
}

// 9. Zero Leakage 및 감사 증거 분리 검증 (audit.jsonl)
func TestExchange_AuditLog_ZeroLeakage(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, auditWriter, auditPath, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt file:write:docs/out.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	childRes, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
		TTL:          30 * time.Minute,
	}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	_ = auditWriter.Close()

	// audit.jsonl 파일에서 이벤트 읽기
	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var events []audit.Event
	for scanner.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("failed to unmarshal audit line: %v", err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	foundExchangeEvent := false
	for _, ev := range events {
		// 원시 JWT 토큰이 이벤트의 어느 필드에도 포함되면 안 됨
		for k, v := range ev.Metadata {
			vStr, ok := v.(string)
			if ok {
				if vStr == parentRes.TokenString || vStr == childRes.TokenString {
					t.Fatalf("CRITICAL ZERO LEAKAGE VIOLATION: raw token found in metadata %s: %s", k, vStr)
				}
			}
		}
		if ev.Action == "token.exchanged" {
			foundExchangeEvent = true
			if ev.Metadata["parent_jti"] != parentRes.Claims.JWTID {
				t.Errorf("expected parent_jti %s, got %v", parentRes.Claims.JWTID, ev.Metadata["parent_jti"])
			}
			if ev.Metadata["child_jti"] != childRes.Claims.JWTID {
				t.Errorf("expected child_jti %s, got %v", childRes.Claims.JWTID, ev.Metadata["child_jti"])
			}
		}
	}
	if !foundExchangeEvent {
		t.Fatal("token.exchanged audit event not found")
	}
}

// 10. 동시성 레이스 검증 (-race)
func TestExchange_Concurrency(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt file:write:docs/out.txt",
		TTL:          1 * time.Hour,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("parent IssueToken failed: %v", err)
	}

	var wg sync.WaitGroup
	workers := 10
	errChan := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			sub := "worker-01"
			if workerID%2 == 1 {
				sub = "worker-02"
			}
			_, err := svc.Exchange(context.Background(), exchange.ExchangeRequest{
				ClientID:     "client-subagent",
				ClientSecret: "subagent-secret-key-02",
				ParentToken:  parentRes.TokenString,
				ChildSubject: sub,
				Scope:        "file:read:docs/plan.txt",
				TTL:          20 * time.Minute,
			}, domain.AuditContext{})
			if err != nil {
				errChan <- err
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Fatalf("concurrent exchange failed: %v", err)
	}
}

// 퍼징 테스트: FuzzScopeValidator
func FuzzScopeValidator(f *testing.F) {
	f.Add("file:read file:write", "file:read")
	f.Add("admin root", "guest")
	f.Add("  file:read   file:write\t\n", "file:read")
	f.Add("", "")

	validator := exchange.NewDownscopeValidator()
	now := time.Now()

	f.Fuzz(func(t *testing.T, parentScope, childScope string) {
		pClaims := &domain.TokenClaims{
			Subject:   "parent",
			Scope:     parentScope,
			ExpiresAt: now.Add(1 * time.Hour).Unix(),
		}
		// 패닉이 발생하지 않는지 검증
		_ = validator.ValidateDownscope(pClaims, "child", childScope, 10*time.Minute, now)
	})
}

// TC-010-09: exchange/service.go 내 문자열 에러 파싱 제거 검증 (부모 토큰 검증 실패 시 strings.Contains 없이 구조화된 Reason 반환)
func TestTC_010_09_Exchange_StructuredParentError(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, _, clk := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          10 * time.Minute,
	}, token.IssueOptions{}, domain.AuditContext{})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// 1. 만료 부모 토큰
	clk.Set(baseTime.Add(20 * time.Minute))
	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:read:docs/plan.txt",
	}, domain.AuditContext{})
	if err == nil {
		t.Fatal("expected expired error, got nil")
	}
	if domain.ReasonFromError(err, "") != domain.ReasonTokenExpired {
		t.Fatalf("expected ReasonTokenExpired, got %s", domain.ReasonFromError(err, ""))
	}
	if domain.ExitCodeFromError(err, domain.ExitInternalError) != domain.ExitTokenInvalid {
		t.Fatalf("expected ExitTokenInvalid (%d), got %d", domain.ExitTokenInvalid, domain.ExitCodeFromError(err, domain.ExitInternalError))
	}
}

// TC-030-10: Token Exchange 거부 시 표준 Action 기록 (token.exchange.deny, decision: deny, reason: DELEGATION_SCOPE_EXCEEDED)
func TestTC_030_10_ExchangeDenyStandardAction(t *testing.T) {
	baseTime := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	svc, issuer, _, _, _, auditPath, _ := setupTestHarness(t, baseTime)

	parentRes, err := issuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-main",
		Scope:        "file:read:docs/plan.txt",
		TTL:          10 * time.Minute,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "trc-ex-setup"})
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	exchangeTraceID := "trc-exchange-999"
	// Scope 확장 시도: read 전용 부모 토큰으로 write 요청 -> DELEGATION_SCOPE_EXCEEDED 거부
	_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
		ClientID:     "client-subagent",
		ClientSecret: "subagent-secret-key-02",
		ParentToken:  parentRes.TokenString,
		ChildSubject: "worker-01",
		Scope:        "file:write:docs/plan.txt",
	}, domain.AuditContext{
		TraceID: exchangeTraceID,
		Actor:   "client-subagent",
	})
	if err == nil {
		t.Fatal("expected scope exceeded error, got nil")
	}

	// 감사 로그 검증
	f, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("failed to open audit file: %v", err)
	}
	defer f.Close()

	var lastEv audit.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err == nil && ev.TraceID == exchangeTraceID {
			lastEv = ev
		}
	}

	if lastEv.Action != "token.exchange.deny" {
		t.Errorf("expected Action 'token.exchange.deny', got %q", lastEv.Action)
	}
	if lastEv.Decision != "deny" {
		t.Errorf("expected Decision 'deny', got %q", lastEv.Decision)
	}
	if lastEv.Reason != string(domain.ReasonDelegationScopeExceeded) {
		t.Errorf("expected Reason %s, got %s", domain.ReasonDelegationScopeExceeded, lastEv.Reason)
	}
}

// 로드맵 16 / 010 TC-010-03: 교환 검증은 완전 일치 유지(D-08)
func TestExchange_Deny_NoPrefixCoverage(t *testing.T) {
	cases := []struct{ parent, child string }{
		{"file:read", "file:read:docs/a.txt"},
		{"net:fetch:127.0.0.1:18080", "net:fetch"},
	}
	for _, c := range cases {
		baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
		svc, issuer, _, _, _, _, _ := setupTestHarness(t, baseTime)
		parentRes, err := issuer.IssueToken(token.IssueRequest{
			ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
			Subject: "orchestrator-main", Scope: c.parent, TTL: time.Hour,
		}, token.IssueOptions{}, domain.AuditContext{})
		if err != nil {
			t.Fatalf("parent IssueToken(%q): %v", c.parent, err)
		}
		_, err = svc.Exchange(context.Background(), exchange.ExchangeRequest{
			ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
			ParentToken: parentRes.TokenString, ChildSubject: "worker-01",
			Scope: c.child, TTL: 30 * time.Minute,
		}, domain.AuditContext{})
		if err == nil || domain.ReasonFromError(err, "") != domain.ReasonDelegationScopeExceeded {
			t.Errorf("%q -> %q: expected DELEGATION_SCOPE_EXCEEDED, got %v", c.parent, c.child, err)
		}
	}
}
