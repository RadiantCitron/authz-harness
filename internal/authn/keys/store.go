package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"authz-harness/internal/domain"
)

var (
	ErrKeyNotFound = errors.New("key not found in key ring")
	ErrKeyRetired  = errors.New("key is retired")
	ErrNoActiveKey = errors.New("no active signing key found")
)

// ZoneAPrivateKeyEntry 는 Zone A 파일에 저장되는 개별 키 모델이다.
type ZoneAPrivateKeyEntry struct {
	KID       string           `json:"kid"`
	KType     string           `json:"kty"` // OKP
	Curve     string           `json:"crv"` // Ed25519
	Algorithm string           `json:"alg"` // EdDSA
	Status    domain.KeyStatus `json:"status"`
	PubKey    string           `json:"pub"`  // Base64URL
	PrivSeed  string           `json:"priv"` // Base64URL (Zero Leakage: Zone A에만 보관)
	CreatedAt time.Time        `json:"created_at"`
	RotatedAt *time.Time       `json:"rotated_at,omitempty"`
	RetiredAt *time.Time       `json:"retired_at,omitempty"`
}

// ZoneAPrivateState 는 Zone A 파일(signing_keys.priv.json)의 전체 구조체다.
type ZoneAPrivateState struct {
	Version   int                    `json:"version"`
	UpdatedAt time.Time              `json:"updated_at"`
	ActiveKID string                 `json:"active_kid"`
	Keys      []ZoneAPrivateKeyEntry `json:"keys"`
}

// Store 는 Zone A와 Zone B의 키 저장소를 관리하는 인터페이스다.
type Store interface {
	LoadPrivate() (*ZoneAPrivateState, error)
	LoadPublic() (*domain.JWKS, error)
	Save(priv *ZoneAPrivateState) error
}

// FileStore 는 flock 기반의 Zone A/B 원자적 동기화 파일 저장소다.
type FileStore struct {
	privPath string
	pubPath  string
	lockPath string
	mu       sync.Mutex
}

// NewFileStore 는 지정된 Zone A 및 Zone B 경로를 관리하는 FileStore 인스턴스를 생성한다.
func NewFileStore(privPath, pubPath string) (*FileStore, error) {
	if privPath == "" || pubPath == "" {
		return nil, errors.New("keys store: privPath and pubPath must not be empty")
	}

	privDir := filepath.Dir(privPath)
	if err := os.MkdirAll(privDir, 0700); err != nil {
		return nil, fmt.Errorf("keys store: failed to create private dir %s: %w", privDir, err)
	}

	pubDir := filepath.Dir(pubPath)
	if err := os.MkdirAll(pubDir, 0755); err != nil {
		return nil, fmt.Errorf("keys store: failed to create public dir %s: %w", pubDir, err)
	}

	return &FileStore{
		privPath: privPath,
		pubPath:  pubPath,
		lockPath: privPath + ".lock",
	}, nil
}

// GenerateEd25519Entry 는 신규 Ed25519 키 쌍을 생성하여 Zone A 키 엔트리를 생성한다.
func GenerateEd25519Entry(kid string, now time.Time) (*ZoneAPrivateKeyEntry, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	// Seed() 는 32바이트 비공개 시드 반환
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

// ToJWKS 는 Zone A 상태에서 Zone B 공개 JWKS 구조체를 투영(Project)한다 (Zero Leakage 보장).
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

// withLock 은 파일 락(flock)을 배타적으로 획득하고 콜백을 실행한다.
func (fs *FileStore) withLock(fn func() error) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	lockFile, err := os.OpenFile(fs.lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("keys store: failed to open lock file %s: %w", fs.lockPath, err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("keys store: failed to acquire flock on %s: %w", fs.lockPath, err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	return fn()
}

// LoadPrivate 은 Zone A 서명 키 파일을 로드한다. 파일이 없으면 nil을 반환한다.
func (fs *FileStore) LoadPrivate() (*ZoneAPrivateState, error) {
	var state *ZoneAPrivateState
	err := fs.withLock(func() error {
		data, err := os.ReadFile(fs.privPath)
		if err != nil {
			if os.IsNotExist(err) {
				state = nil
				return nil
			}
			return fmt.Errorf("keys store: read private error: %w", err)
		}

		var s ZoneAPrivateState
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("keys store: unmarshal private error: %w", err)
		}
		state = &s
		return nil
	})
	return state, err
}

// LoadPublic 은 Zone B 공개 검증 키(JWKS) 파일을 로드한다.
func (fs *FileStore) LoadPublic() (*domain.JWKS, error) {
	var jwks *domain.JWKS
	err := fs.withLock(func() error {
		data, err := os.ReadFile(fs.pubPath)
		if err != nil {
			if os.IsNotExist(err) {
				jwks = nil
				return nil
			}
			return fmt.Errorf("keys store: read public error: %w", err)
		}

		var j domain.JWKS
		if err := json.Unmarshal(data, &j); err != nil {
			return fmt.Errorf("keys store: unmarshal public error: %w", err)
		}
		jwks = &j
		return nil
	})
	return jwks, err
}

// Save 는 Zone A와 Zone B를 배타적 락 하에서 임시 파일 작성 및 Atomic Rename으로 동시 저장한다.
func (fs *FileStore) Save(priv *ZoneAPrivateState) error {
	return fs.withLock(func() error {
		// 1. Zone A 원자적 저장 (0600)
		privData, err := json.MarshalIndent(priv, "", "  ")
		if err != nil {
			return fmt.Errorf("keys store: marshal private error: %w", err)
		}
		privTmp := fmt.Sprintf("%s.tmp.%d", fs.privPath, time.Now().UnixNano())
		if err := os.WriteFile(privTmp, append(privData, '\n'), 0600); err != nil {
			return fmt.Errorf("keys store: write tmp private error: %w", err)
		}
		if err := os.Rename(privTmp, fs.privPath); err != nil {
			_ = os.Remove(privTmp)
			return fmt.Errorf("keys store: rename private error: %w", err)
		}

		// 2. Zone B 원자적 저장 (0644, Zero Leakage)
		pubJWKS := priv.ToJWKS()
		pubData, err := json.MarshalIndent(pubJWKS, "", "  ")
		if err != nil {
			return fmt.Errorf("keys store: marshal public error: %w", err)
		}
		pubTmp := fmt.Sprintf("%s.tmp.%d", fs.pubPath, time.Now().UnixNano())
		if err := os.WriteFile(pubTmp, append(pubData, '\n'), 0644); err != nil {
			return fmt.Errorf("keys store: write tmp public error: %w", err)
		}
		if err := os.Rename(pubTmp, fs.pubPath); err != nil {
			_ = os.Remove(pubTmp)
			return fmt.Errorf("keys store: rename public error: %w", err)
		}

		return nil
	})
}
