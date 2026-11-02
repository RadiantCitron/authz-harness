package keys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

type mockClock struct {
	t time.Time
}

func (m *mockClock) Now() time.Time {
	return m.t
}

func (m *mockClock) Add(d time.Duration) {
	m.t = m.t.Add(d)
}

func setupTestStore(t *testing.T) (*FileStore, string, string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, ".authz-state", "private", "signing_keys.priv.json")
	pubPath := filepath.Join(tmpDir, ".authz-state", "public", "jwks.pub.json")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	store, err := NewFileStore(privPath, pubPath)
	if err != nil {
		t.Fatalf("failed to create FileStore: %v", err)
	}

	return store, privPath, pubPath, auditPath
}

func TestKeyManager_Lifecycle(t *testing.T) {
	store, privPath, pubPath, auditPath := setupTestStore(t)
	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("failed to create audit writer: %v", err)
	}
	defer auditWriter.Close()

	clock := &mockClock{t: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)}

	// 1. 초기화: 자동 최초 키 생성 검증 (시나리오 1)
	mgr, err := NewManager(store, auditWriter, WithClock(clock))
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	keys, err := mgr.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 initial key, got %d", len(keys))
	}
	initialKID := keys[0].KID
	if keys[0].Status != domain.KeyStatusActive {
		t.Fatalf("expected initial key status active, got %s", keys[0].Status)
	}
	if keys[0].Algorithm != "EdDSA" || keys[0].Curve != "Ed25519" {
		t.Fatalf("unexpected key alg/crv: %s/%s", keys[0].Algorithm, keys[0].Curve)
	}

	// Active signing key 검증
	signingKey, err := mgr.GetActiveSigningKey()
	if err != nil {
		t.Fatalf("GetActiveSigningKey failed: %v", err)
	}
	if signingKey.KID != initialKID {
		t.Fatalf("expected signing key kid %s, got %s", initialKID, signingKey.KID)
	}

	// 2. 키 회전 검증 (시나리오 2)
	clock.Add(time.Hour)
	auditCtx := domain.AuditContext{
		TraceID: "test-trace-rotate",
		Actor:   "admin",
		Reason:  "periodic rotation",
	}
	rotatedJWK, err := mgr.RotateKey(auditCtx)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	newActiveKID := rotatedJWK.KID
	if newActiveKID == initialKID {
		t.Fatalf("expected new kid for rotated key, got same %s", newActiveKID)
	}

	// 키 목록 상태 검증
	keys, err = mgr.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", len(keys))
	}

	var oldKey, newKey *domain.JWK
	for i := range keys {
		if keys[i].KID == initialKID {
			oldKey = &keys[i]
		} else if keys[i].KID == newActiveKID {
			newKey = &keys[i]
		}
	}

	if oldKey == nil || oldKey.Status != domain.KeyStatusVerifyOnly {
		t.Fatalf("expected old key status verify-only, got %+v", oldKey)
	}
	if newKey == nil || newKey.Status != domain.KeyStatusActive {
		t.Fatalf("expected new key status active, got %+v", newKey)
	}

	// 활성 서명키는 신규 키여야 함
	signingKey, err = mgr.GetActiveSigningKey()
	if err != nil {
		t.Fatalf("GetActiveSigningKey failed: %v", err)
	}
	if signingKey.KID != newActiveKID {
		t.Fatalf("expected active signing key to be %s, got %s", newActiveKID, signingKey.KID)
	}

	// 구 키도 검증용으로는 조회 가능해야 함
	verKeyOld, err := mgr.GetVerificationKey(initialKID)
	if err != nil {
		t.Fatalf("GetVerificationKey for old key failed: %v", err)
	}
	if verKeyOld.KID != initialKID {
		t.Fatalf("expected old ver key kid %s, got %s", initialKID, verKeyOld.KID)
	}

	// 3. 키 폐기 검증 (시나리오 3)
	clock.Add(time.Hour)
	revokeCtx := domain.AuditContext{
		TraceID: "test-trace-revoke",
		Actor:   "security-ops",
		Reason:  "key compromised",
	}
	if err := mgr.RevokeKey(initialKID, revokeCtx); err != nil {
		t.Fatalf("RevokeKey failed: %v", err)
	}

	// 폐기된 키 조회 시 ErrKeyRetired 반환 검증
	_, err = mgr.GetVerificationKey(initialKID)
	if err != ErrKeyRetired {
		t.Fatalf("expected ErrKeyRetired for revoked key, got %v", err)
	}

	// 4. Zero Leakage 검증 (시나리오 4)
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("failed to read public jwks file: %v", err)
	}
	pubContent := string(pubBytes)
	if strings.Contains(pubContent, `"priv"`) || strings.Contains(pubContent, `"d"`) {
		t.Fatalf("Zero Leakage violation: public JWKS contains private key fields! content:\n%s", pubContent)
	}

	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}
	auditContent := string(auditBytes)
	if strings.Contains(auditContent, `"priv"`) || strings.Contains(auditContent, `"d"`) {
		t.Fatalf("Zero Leakage violation: audit log contains private key fields! content:\n%s", auditContent)
	}

	// Zone A 비밀키는 존재해야 함
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("failed to read private key file: %v", err)
	}
	if !strings.Contains(string(privBytes), `"priv"`) {
		t.Fatalf("expected private key file to contain priv seed")
	}
}

func TestKeyManager_Concurrency(t *testing.T) {
	store, _, _, auditPath := setupTestStore(t)
	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("failed to create audit writer: %v", err)
	}
	defer auditWriter.Close()

	mgr, err := NewManager(store, auditWriter)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			if idx%3 == 0 {
				_, _ = mgr.RotateKey(domain.AuditContext{
					TraceID: fmt.Sprintf("trace-%d", idx),
					Actor:   "concurrent-worker",
					Reason:  "rotation test",
				})
			} else {
				_, _ = mgr.ListKeys()
				_, _ = mgr.GetActiveSigningKey()
			}
		}(i)
	}

	wg.Wait()

	keys, err := mgr.ListKeys()
	if err != nil {
		t.Fatalf("concurrent ListKeys failed: %v", err)
	}
	if len(keys) < 1 {
		t.Fatalf("expected at least 1 key after concurrent operations, got %d", len(keys))
	}
}

// TC-010-06: keys.Manager의 domain.Clock 단일 사용 및 가상 시계 주입 검증
func TestTC_010_06_KeysManager_SingleDomainClock(t *testing.T) {
	store, _, _, auditPath := setupTestStore(t)
	auditWriter, err := audit.NewJSONLWriter(auditPath)
	if err != nil {
		t.Fatalf("failed to create audit writer: %v", err)
	}
	defer auditWriter.Close()

	fixedBase := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	mockBase := &mockClock{t: fixedBase}
	offset := 24 * time.Hour
	offsetClock := domain.NewOffsetClock(mockBase, offset) // 2026-11-03 12:00:00

	mgr, err := NewManager(store, auditWriter, WithClock(offsetClock))
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	newKey, err := mgr.RotateKey(domain.AuditContext{
		TraceID: "tc-010-06-trace",
		Actor:   "admin",
		Reason:  "test clock injection",
	})
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	expectedTime := fixedBase.Add(offset)
	if !newKey.CreatedAt.Equal(expectedTime) {
		t.Fatalf("expected CreatedAt %v, got %v", expectedTime, newKey.CreatedAt)
	}
}
