// Package keys 는 Zone A 비밀키 저장소와 Zone B 공개 JWKS 의 원자적 파일 동기화를 제공한다.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

var (
	ErrKeyNotFound = errors.New("key not found in key ring")
	ErrKeyRetired  = errors.New("key is retired")
	ErrNoActiveKey = errors.New("no active signing key found")

	// ErrVerifyOnlyStore 는 Zone A 없이 조립된 저장소에 키 변경을 시도했다는 뜻이다.
	ErrVerifyOnlyStore = errors.New("keys store: cannot update in verify-only mode (privStore is nil)")
)

// ZoneAPrivateKeyEntry 는 Zone A 파일(signing_keys.priv.json)에 영속화되는 개별 비밀키 엔트리 모델이다.
type ZoneAPrivateKeyEntry struct {
	KID       string           `json:"kid"`
	KType     string           `json:"kty"` // OKP
	Curve     string           `json:"crv"` // Ed25519
	Algorithm string           `json:"alg"` // EdDSA
	Status    domain.KeyStatus `json:"status"`
	PubKey    string           `json:"pub"`  // Base64URL 공개키
	PrivSeed  string           `json:"priv"` // Base64URL 32바이트 비공개 시드 (Zero Leakage: Zone A 에만 보관)
	CreatedAt time.Time        `json:"created_at"`
	RotatedAt *time.Time       `json:"rotated_at,omitempty"`
	RetiredAt *time.Time       `json:"retired_at,omitempty"`
}

// ZoneAPrivateState 는 Zone A 파일의 전체 JSON 구조체다.
type ZoneAPrivateState struct {
	Version   int                    `json:"version"`
	UpdatedAt time.Time              `json:"updated_at"`
	ActiveKID string                 `json:"active_kid"`
	Keys      []ZoneAPrivateKeyEntry `json:"keys"`
}

// Store 는 Zone A 와 Zone B 의 키 저장소를 관리하는 도메인 포트 인터페이스(DIP)다.
type Store interface {
	LoadPrivate() (*ZoneAPrivateState, error)
	LoadPublic() (*domain.JWKS, error)
	Update(fn func(priv *ZoneAPrivateState) error) error
}

// FileStore 는 storage.AtomicFileStore 기반의 Zone A/B 원자적 동기화 파일 저장소다.
type FileStore struct {
	privPath  string
	pubPath   string
	privStore *storage.AtomicFileStore[ZoneAPrivateState]
	pubStore  *storage.AtomicFileStore[domain.JWKS]
}

// NewFileStore 는 지정된 Zone A 및 Zone B 경로를 관리하는 FileStore 인스턴스를 생성한다.
// 검증 전용(Zone B only / VerifyOnly)인 경우 privPath 는 빈 문자열("")로 주입되어 개인키 접근을 원천 차단한다.
func NewFileStore(privPath, pubPath string) (*FileStore, error) {
	if pubPath == "" {
		return nil, errors.New("keys store: pubPath must not be empty")
	}

	if privPath != "" {
		privDir := filepath.Dir(privPath)
		if err := os.MkdirAll(privDir, 0700); err != nil {
			return nil, fmt.Errorf("keys store: failed to create private dir %s: %w", privDir, err)
		}
		// MkdirAll 은 이미 존재하는 폴더의 권한을 바꾸지 않으므로 Zone A 폴더를 직접 0700 으로 좁힌다.
		// 경로에 폴더가 없으면(".") 사용자의 작업 폴더이므로 건드리지 않는다.
		if privDir != "." {
			if err := os.Chmod(privDir, 0700); err != nil {
				return nil, fmt.Errorf("keys store: failed to restrict private dir %s: %w", privDir, err)
			}
		}
	}

	pubDir := filepath.Dir(pubPath)
	if err := os.MkdirAll(pubDir, 0755); err != nil {
		return nil, fmt.Errorf("keys store: failed to create public dir %s: %w", pubDir, err)
	}

	lockPath := pubPath + ".lock"
	if privPath != "" {
		lockPath = privPath + ".lock"
	}

	var privStore *storage.AtomicFileStore[ZoneAPrivateState]
	if privPath != "" {
		privStore = storage.NewAtomicFileStore[ZoneAPrivateState](
			privPath,
			storage.WithPerm[ZoneAPrivateState](0600),
			storage.WithLockPath[ZoneAPrivateState](lockPath),
			storage.WithDefault(func() *ZoneAPrivateState {
				return &ZoneAPrivateState{}
			}),
		)
	}

	pubStore := storage.NewAtomicFileStore[domain.JWKS](
		pubPath,
		storage.WithPerm[domain.JWKS](0644),
		storage.WithLockPath[domain.JWKS](lockPath),
		storage.WithDefault(func() *domain.JWKS {
			return &domain.JWKS{}
		}),
	)

	return &FileStore{
		privPath:  privPath,
		pubPath:   pubPath,
		privStore: privStore,
		pubStore:  pubStore,
	}, nil
}

// GenerateEd25519Entry 는 crypto/ed25519 표준 패키지를 호출하여 암호학적으로 안전한 신규 Ed25519 키 쌍을 생성한다.
func GenerateEd25519Entry(kid string, now time.Time) (*ZoneAPrivateKeyEntry, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	// Seed() 는 32바이트 비공개 시드를 반환한다 (Ed25519 개인키 복원 원천)
	seed := priv.Seed()

	return &ZoneAPrivateKeyEntry{
		KID:       kid,
		KType:     "OKP",
		Curve:     "Ed25519",
		Algorithm: "EdDSA",
		Status:    domain.KeyStatusActive,
		PubKey:    base64.RawURLEncoding.EncodeToString(pub),
		PrivSeed:  base64.RawURLEncoding.EncodeToString(seed),
		CreatedAt: now,
	}, nil
}

// ToJWKS 는 Zone A 상태로부터 Zone B 공개 JWKS 구조체를 투영(Projection)한다.
// Zero Leakage 보안 원칙에 따라 비공개 시드(PrivSeed)는 일절 포함되지 않고 오직 공개키 메타데이터만 복사된다.
func (s *ZoneAPrivateState) ToJWKS() *domain.JWKS {
	jwkList := make([]domain.JWK, len(s.Keys))
	for i, k := range s.Keys {
		jwkList[i] = domain.JWK{
			KID:       k.KID,
			KType:     k.KType,
			Curve:     k.Curve,
			Algorithm: k.Algorithm,
			Use:       "sig",
			Status:    k.Status,
			PublicKey: k.PubKey,
			CreatedAt: k.CreatedAt,
			RotatedAt: k.RotatedAt,
			RetiredAt: k.RetiredAt,
		}
	}

	return &domain.JWKS{
		Version:   s.Version,
		UpdatedAt: s.UpdatedAt,
		Keys:      jwkList,
	}
}

// LoadPrivate 은 Zone A 서명 키 파일을 로드한다. 파일이 없거나 VerifyOnly 모드면 nil 을 반환한다.
func (fs *FileStore) LoadPrivate() (*ZoneAPrivateState, error) {
	if fs.privStore == nil {
		return nil, nil
	}

	state, err := fs.privStore.Read()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("keys store: read private error: %w", err)
	}
	return state, nil
}

// LoadPublic 은 Zone B 공개 검증 키(JWKS) 파일을 로드한다.
func (fs *FileStore) LoadPublic() (*domain.JWKS, error) {
	jwks, err := fs.pubStore.Read()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("keys store: read public error: %w", err)
	}
	return jwks, nil
}

// Update 는 배타적 락(LOCK_EX) 하에서 Zone A 비밀키 상태를 읽고 fn 으로 변이한 후,
// Zone A 파일(0600)과 Zone B 공개 JWKS 파일(0644)을 동일 배타 락 구간 내에서 원자적으로 동시 갱신한다.
func (fs *FileStore) Update(fn func(priv *ZoneAPrivateState) error) error {
	if fs.privStore == nil {
		return ErrVerifyOnlyStore
	}
	if fn == nil {
		return errors.New("keys store: update function must not be nil")
	}

	return fs.privStore.Update(func(priv *ZoneAPrivateState) error {
		if err := fn(priv); err != nil {
			return err
		}

		// Zone A 가 갱신된 동일 배타 락 구간 내에서 Zone B 공개 JWKS 를 원자적으로 동기화 (0644, Zero Leakage)
		pubJWKS := priv.ToJWKS()
		if err := fs.pubStore.WriteUnlocked(pubJWKS); err != nil {
			return fmt.Errorf("keys store: write public error: %w", err)
		}

		return nil
	})
}
