package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// Clock 은 시간 주입 포트 인터페이스다.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now().UTC()
}

// KeyManager 는 Zone A/B 키 링의 수명주기를 제어하는 인터페이스다.
type KeyManager interface {
	// ListKeys 는 현재 키 링의 모든 공개 메타데이터와 상태를 반환한다.
	ListKeys() ([]domain.JWK, error)

	// GetActiveSigningKey 는 토큰 서명에 사용할 현재 활성(active) 개인키를 반환한다.
	GetActiveSigningKey() (*domain.SigningKey, error)

	// GetVerificationKey 는 kid에 해당하는 공개 검증 키를 반환한다. (retired 키는 ErrKeyRetired 반환)
	GetVerificationKey(kid string) (*domain.JWK, error)

	// RotateKey 는 새 Ed25519 키를 생성하여 active로 설정하고 기존 active 키를 verify-only로 전이한다.
	RotateKey(auditCtx domain.AuditContext) (*domain.JWK, error)

	// RevokeKey 는 지정한 kid의 키를 retired 상태로 전이하여 즉시 무효화한다.
	RevokeKey(kid string, auditCtx domain.AuditContext) error
}

// Manager 는 KeyManager 인터페이스를 구현하는 엔진이다.
type Manager struct {
	store Store
	auditWriter audit.Writer
	clock Clock
}

// ManagerOption 은 Manager 옵션 구성자다.
type ManagerOption func(*Manager)

// WithClock 은 가상 시간을 주입하기 위한 옵션이다.
func WithClock(c Clock) ManagerOption {
	return func(m *Manager) {
		m.clock = c
	}
}

// NewManager 는 주어진 저장소와 감사 로거를 바탕으로 Manager를 초기화한다.
// 키 링이 존재하지 않으면 첫 번째 active 키를 자동으로 생성하여 초기화한다.
// 단, 공개 검증 전용(Zone B only) 환경에서는 키 생성을 건너뛴다.
func NewManager(store Store, auditLog audit.Writer, opts ...ManagerOption) (*Manager, error) {
	if store == nil {
		return nil, errors.New("keys manager: store must not be nil")
	}

	m := &Manager{
		store:       store,
		auditWriter: auditLog,
		clock:       realClock{},
	}

	for _, opt := range opts {
		opt(m)
	}

	// 초기 로드 및 부트스트랩 확인
	privState, err := m.store.LoadPrivate()
	if err != nil {
		return nil, fmt.Errorf("keys manager: failed to load private state: %w", err)
	}

	if privState == nil || len(privState.Keys) == 0 {
		// 공개 키만 있고 비밀 키가 없는 검증 전용 모드(Zone B only)인지 확인
		pub, pubErr := m.store.LoadPublic()
		if pubErr == nil && pub != nil && len(pub.Keys) > 0 {
			// 이미 공개 키가 존재하므로 private 키 자동 생성을 건너뛴다.
			return m, nil
		}

		// 최초 활성 키 자동 부트스트랩
		now := m.clock.Now()
		kid := fmt.Sprintf("key-%s-01", now.Format("20060102150405"))
		entry, err := GenerateEd25519Entry(kid, now)
		if err != nil {
			return nil, fmt.Errorf("keys manager: failed to generate initial key: %w", err)
		}

		newState := &ZoneAPrivateState{
			Version:   1,
			UpdatedAt: now,
			ActiveKID: kid,
			Keys:      []ZoneAPrivateKeyEntry{*entry},
		}

		if err := m.store.Save(newState); err != nil {
			if pubErr == nil {
				return m, nil
			}
			return nil, fmt.Errorf("keys manager: failed to save initial state: %w", err)
		}

		if m.auditWriter != nil {
			_ = m.auditWriter.Log(audit.Event{
				Timestamp: now,
				TraceID:   fmt.Sprintf("init-%s", kid),
				Actor:     "system",
				Action:    "key.created",
				Success:   true,
				Metadata: map[string]interface{}{
					"kid":    kid,
					"alg":    entry.Algorithm,
					"status": entry.Status,
				},
			})
		}
	}

	return m, nil
}

// ListKeys 는 공개된 키 목록을 반환한다.
func (m *Manager) ListKeys() ([]domain.JWK, error) {
	pub, err := m.store.LoadPublic()
	if err != nil {
		return nil, fmt.Errorf("keys manager: failed to load public keys: %w", err)
	}
	if pub == nil {
		return []domain.JWK{}, nil
	}
	return pub.Keys, nil
}

// GetActiveSigningKey 는 현재 활성 키의 서명용 개인키 객체를 반환한다.
func (m *Manager) GetActiveSigningKey() (*domain.SigningKey, error) {
	privState, err := m.store.LoadPrivate()
	if err != nil {
		return nil, fmt.Errorf("keys manager: failed to load private state: %w", err)
	}
	if privState == nil || privState.ActiveKID == "" {
		return nil, ErrNoActiveKey
	}

	for _, k := range privState.Keys {
		if k.KID == privState.ActiveKID && k.Status == domain.KeyStatusActive {
			seed, err := base64.RawURLEncoding.DecodeString(k.PrivSeed)
			if err != nil {
				return nil, fmt.Errorf("keys manager: invalid private seed encoding: %w", err)
			}
			privKey := ed25519.NewKeyFromSeed(seed)
			pubKey := privKey.Public().(ed25519.PublicKey)

			return &domain.SigningKey{
				KID:        k.KID,
				Algorithm:  k.Algorithm,
				Status:     k.Status,
				PrivateKey: privKey,
				PublicKey:  pubKey,
				CreatedAt:  k.CreatedAt,
			}, nil
		}
	}

	return nil, ErrNoActiveKey
}

// GetVerificationKey 는 kid에 일치하는 검증용 공개키를 조회한다.
func (m *Manager) GetVerificationKey(kid string) (*domain.JWK, error) {
	keys, err := m.ListKeys()
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if k.KID == kid {
			if k.Status == domain.KeyStatusRetired {
				return nil, ErrKeyRetired
			}
			return &k, nil
		}
	}

	return nil, ErrKeyNotFound
}

// RotateKey 는 새 키를 active로 생성하고 기존 active 키를 verify-only로 전이한다.
func (m *Manager) RotateKey(auditCtx domain.AuditContext) (*domain.JWK, error) {
	privState, err := m.store.LoadPrivate()
	if err != nil {
		return nil, fmt.Errorf("keys manager: failed to load private state: %w", err)
	}
	if privState == nil {
		return nil, errors.New("keys manager: private state not found")
	}

	now := m.clock.Now()
	newKID := fmt.Sprintf("key-%s-%02d", now.Format("20060102150405"), len(privState.Keys)+1)
	newEntry, err := GenerateEd25519Entry(newKID, now)
	if err != nil {
		return nil, fmt.Errorf("keys manager: failed to generate new key: %w", err)
	}

	var oldActiveKID string
	// 기존 active 키를 verify-only로 변경
	for i := range privState.Keys {
		if privState.Keys[i].Status == domain.KeyStatusActive {
			privState.Keys[i].Status = domain.KeyStatusVerifyOnly
			privState.Keys[i].RotatedAt = &now
			oldActiveKID = privState.Keys[i].KID
		}
	}

	privState.Keys = append(privState.Keys, *newEntry)
	privState.ActiveKID = newKID
	privState.UpdatedAt = now
	privState.Version++

	if err := m.store.Save(privState); err != nil {
		return nil, fmt.Errorf("keys manager: failed to save rotated keys: %w", err)
	}

	if m.auditWriter != nil {
		_ = m.auditWriter.Log(audit.Event{
			Timestamp: now,
			TraceID:   auditCtx.TraceID,
			Actor:     auditCtx.Actor,
			Action:    "key.rotated",
			Success:   true,
			Reason:    auditCtx.Reason,
			Metadata: map[string]interface{}{
				"old_active_kid": oldActiveKID,
				"new_active_kid": newKID,
				"alg":            newEntry.Algorithm,
			},
		})
	}

	jwk := domain.JWK{
		KID:       newEntry.KID,
		KType:     newEntry.KType,
		Curve:     newEntry.Curve,
		Algorithm: newEntry.Algorithm,
		Use:       "sig",
		Status:    newEntry.Status,
		PublicKey: newEntry.PubKey,
		CreatedAt: newEntry.CreatedAt,
	}

	return &jwk, nil
}

// RevokeKey 는 지정한 kid의 키를 retired 상태로 전이한다.
func (m *Manager) RevokeKey(kid string, auditCtx domain.AuditContext) error {
	if kid == "" {
		return errors.New("keys manager: kid must not be empty")
	}

	privState, err := m.store.LoadPrivate()
	if err != nil {
		return fmt.Errorf("keys manager: failed to load private state: %w", err)
	}
	if privState == nil {
		return errors.New("keys manager: private state not found")
	}

	found := false
	now := m.clock.Now()

	for i := range privState.Keys {
		if privState.Keys[i].KID == kid {
			found = true
			if privState.Keys[i].Status == domain.KeyStatusRetired {
				// 이미 폐기된 키
				return nil
			}

			privState.Keys[i].Status = domain.KeyStatusRetired
			privState.Keys[i].RetiredAt = &now

			// 만약 현재 active 키가 revoke 된 경우 active_kid 해제
			if privState.ActiveKID == kid {
				privState.ActiveKID = ""
			}
			break
		}
	}

	if !found {
		return ErrKeyNotFound
	}

	privState.UpdatedAt = now
	privState.Version++

	if err := m.store.Save(privState); err != nil {
		return fmt.Errorf("keys manager: failed to save revoked state: %w", err)
	}

	if m.auditWriter != nil {
		_ = m.auditWriter.Log(audit.Event{
			Timestamp: now,
			TraceID:   auditCtx.TraceID,
			Actor:     auditCtx.Actor,
			Action:    "key.revoked",
			Success:   true,
			Reason:    auditCtx.Reason,
			Metadata: map[string]interface{}{
				"revoked_kid": kid,
			},
		})
	}

	return nil
}
