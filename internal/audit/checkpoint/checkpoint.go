// Package checkpoint 는 감사 해시 체인의 꼬리 절단·전체 재작성·파일 삭제를 탐지하는
// Ed25519 서명 체크포인트를 제공한다. Zone A 감사 전용 키를 다루므로 internal/audit 와 분리돼 있으며,
// 워커 경로는 이 패키지를 import 하지 않는다(TC-060-02).
//
// 한계: 체크포인트는 서명 시점까지의 레코드만 보호하며, 오래된 유효 체크포인트로의 되돌리기(rollback)는 막지 못한다.
package checkpoint

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

// Checkpoint 는 서명된 감사 체인 스냅샷이다. Signature 는 base64url 이다.
type Checkpoint struct {
	LineCount int    `json:"line_count"`
	HeadHash  string `json:"head_hash"`
	Timestamp string `json:"timestamp"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type privFile struct {
	KeyID      string `json:"kid"`
	PrivateKey string `json:"private_key"`
}

type pubFile struct {
	KeyID     string `json:"kid"`
	PublicKey string `json:"public_key"`
}

var b64 = base64.RawURLEncoding

func kidOf(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "audit-ckpt-" + hex.EncodeToString(h[:8])
}

func canonical(c Checkpoint) []byte {
	return []byte(fmt.Sprintf("audit-ckpt-v1|%d|%s|%s|%s", c.LineCount, c.HeadHash, c.Timestamp, c.KeyID))
}

// EnsureKeyPair 는 감사 전용 키 쌍을 확보한다. 둘 다 없으면 생성하고, 하나만 있으면 Fail-Closed 오류를 낸다.
func EnsureKeyPair(privPath, pubPath string, clock domain.Clock) (string, error) {
	_, privErr := os.Stat(privPath)
	_, pubErr := os.Stat(pubPath)
	privExists, pubExists := privErr == nil, pubErr == nil

	switch {
	case privExists && pubExists:
		priv, err := loadPriv(privPath)
		if err != nil {
			return "", err
		}
		pub, kid, err := loadPub(pubPath)
		if err != nil {
			return "", err
		}
		if kidOf(priv.Public().(ed25519.PublicKey)) != kid || !priv.Public().(ed25519.PublicKey).Equal(pub) {
			return "", errors.New("checkpoint: audit key pair mismatch")
		}
		return kid, nil
	case privExists != pubExists:
		return "", errors.New("checkpoint: audit key pair is incomplete (one file missing)")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("checkpoint: key generation failed: %w", err)
	}
	kid := kidOf(pub)
	pb, _ := json.Marshal(privFile{KeyID: kid, PrivateKey: b64.EncodeToString(priv)})
	ub, _ := json.Marshal(pubFile{KeyID: kid, PublicKey: b64.EncodeToString(pub)})
	if err := storage.AtomicWriteFile(privPath, pb, 0o600); err != nil {
		return "", fmt.Errorf("checkpoint: write private key: %w", err)
	}
	if err := storage.AtomicWriteFile(pubPath, ub, 0o644); err != nil {
		return "", fmt.Errorf("checkpoint: write public key: %w", err)
	}
	return kid, nil
}

func loadPriv(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: read private key: %w", err)
	}
	var f privFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("checkpoint: parse private key: %w", err)
	}
	raw, err := b64.DecodeString(f.PrivateKey)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("checkpoint: invalid private key")
	}
	return ed25519.PrivateKey(raw), nil
}

func loadPub(path string) (ed25519.PublicKey, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("checkpoint: read public key: %w", err)
	}
	var f pubFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, "", fmt.Errorf("checkpoint: parse public key: %w", err)
	}
	raw, err := b64.DecodeString(f.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", errors.New("checkpoint: invalid public key")
	}
	pub := ed25519.PublicKey(raw)
	return pub, kidOf(pub), nil
}

// readLines 는 감사 파일의 비어 있지 않은 줄을 읽는다. 파일이 없으면 nil 이다.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), audit.MaxRecordBytes+1)
	var lines []string
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}

func currHashOf(line string) (string, error) {
	var ev audit.Event
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return "", err
	}
	return ev.EffectiveCurrHash(), nil
}

// Create 는 현재 감사 체인의 (줄 수, 마지막 curr_hash)에 서명한 체크포인트를 outPath 에 쓴다.
func Create(auditPath, privPath, pubPath, outPath string, clock domain.Clock) (*Checkpoint, error) {
	var lines []string
	// 감사 잠금 안에서는 읽기만 한다(키 파일·다른 잠금 접근 금지).
	err := storage.WithFileLock(auditPath+".lock", syscall.LOCK_SH, func() error {
		var rerr error
		lines, rerr = readLines(auditPath)
		return rerr
	})
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("checkpoint: read audit: %v", err), err)
	}
	if len(lines) == 0 {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "checkpoint: audit log is missing or empty", nil)
	}
	if err := audit.VerifyHashChain(auditPath); err != nil {
		return nil, err
	}
	head, err := currHashOf(lines[len(lines)-1])
	if err != nil || head == "" {
		return nil, domain.NewError(domain.ReasonAuditIntegrityBroken, "checkpoint: last record has no curr_hash", err)
	}
	kid, err := EnsureKeyPair(privPath, pubPath, clock)
	if err != nil {
		return nil, err
	}
	priv, err := loadPriv(privPath)
	if err != nil {
		return nil, err
	}
	c := Checkpoint{
		LineCount: len(lines),
		HeadHash:  head,
		Timestamp: clock.Now().UTC().Format(time.RFC3339Nano),
		KeyID:     kid,
	}
	c.Signature = b64.EncodeToString(ed25519.Sign(priv, canonical(c)))
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("checkpoint: marshal: %w", err)
	}
	if err := storage.AtomicWriteFile(outPath, data, 0o644); err != nil {
		return nil, fmt.Errorf("checkpoint: write: %w", err)
	}
	return &c, nil
}

func mismatch(msg string, err error) error {
	return domain.NewError(domain.ReasonAuditCheckpointMismatch, msg, err)
}

// Verify 는 해시 체인과 서명 체크포인트를 대조한다. 키를 생성하지 않는다.
func Verify(auditPath, ckptPath, pubPath string) error {
	if err := audit.VerifyHashChain(auditPath); err != nil {
		return err
	}
	cb, err := os.ReadFile(ckptPath)
	if err != nil {
		return mismatch("checkpoint file unreadable", err)
	}
	var c Checkpoint
	if err := json.Unmarshal(cb, &c); err != nil {
		return mismatch("checkpoint file malformed", err)
	}
	pub, kid, err := loadPub(pubPath)
	if err != nil {
		return mismatch("audit public key unreadable", err)
	}
	if c.KeyID != kid {
		return mismatch("checkpoint key id does not match public key", nil)
	}
	sig, err := b64.DecodeString(c.Signature)
	if err != nil || !ed25519.Verify(pub, canonical(c), sig) {
		return mismatch("checkpoint signature invalid", err)
	}

	lines, err := readLines(auditPath)
	if err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("read audit: %v", err), err)
	}
	if len(lines) < c.LineCount || c.LineCount <= 0 {
		return domain.NewError(domain.ReasonAuditTruncationDetected,
			fmt.Sprintf("audit log has %d records, checkpoint covers %d", len(lines), c.LineCount), nil)

	}
	h, err := currHashOf(lines[c.LineCount-1])
	if err != nil || h != c.HeadHash {
		return mismatch("record at checkpoint line does not match head hash (rewrite suspected)", err)
	}
	return nil
}
