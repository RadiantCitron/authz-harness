package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

// RecoveryResult 는 RecoverIncompleteTail 의 결과다. Recovered 가 false 면 할 일이 없었다.
type RecoveryResult struct {
	Recovered      bool
	PartialPath    string
	TruncatedBytes int
	TruncatedSHA   string
}

// RecoverIncompleteTail 은 기록 도중 충돌로 잘린 마지막 줄을 옆 파일로 보존하고 사슬을 복구한다.
// 「잘린 꼬리」(줄바꿈 없이 끝나는 깨진 JSON, 앞 사슬은 온전)가 아니면 아무것도 바꾸지 않고 오류를 반환한다.
// 복구 사실은 audit.recover 이벤트로 사슬에 남는다(plan-008 W2).
func RecoverIncompleteTail(path string, clock domain.Clock) (*RecoveryResult, error) {
	lockPath := path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to open lock file %s: %v", lockPath, err), err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to acquire flock on %s: %v", lockPath, err), err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	verr := VerifyHashChain(path)
	if verr == nil {
		return &RecoveryResult{}, nil
	}
	if !isReason(verr, domain.ReasonAuditTailIncomplete) {
		return nil, verr
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to read audit file: %v", err), err)
	}
	keep := bytes.LastIndexByte(data, '\n') + 1
	partial := data[keep:]
	sum := sha256.Sum256(partial)
	res := &RecoveryResult{
		Recovered:      true,
		PartialPath:    path + ".partial-" + clock.Now().UTC().Format("20060102T150405.000000000Z"),
		TruncatedBytes: len(partial),
		TruncatedSHA:   hex.EncodeToString(sum[:]),
	}

	if err := storage.AtomicWriteFile(res.PartialPath, partial, 0o600); err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to preserve truncated tail: %v", err), err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to open audit file: %v", err), err)
	}
	if err := f.Truncate(int64(keep)); err != nil {
		f.Close()
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to truncate audit file: %v", err), err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to sync audit file: %v", err), err)
	}
	f.Close()

	w, err := NewJSONLWriter(path)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, "audit", err.Error(), err)
	}
	defer w.Close()
	ev := Event{
		Timestamp: clock.Now().UTC().Truncate(time.Nanosecond),
		TraceID:   "audit-recover",
		Actor:     "operator",
		Action:    "audit.recover",
		Resource:  partialBase(res.PartialPath),
		Decision:  "allow",
		Reason:    string(domain.ReasonAuditTailIncomplete),
		Success:   true,
		Metadata: map[string]interface{}{
			"truncated_bytes":  len(partial),
			"truncated_sha256": res.TruncatedSHA,
		},
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.appendLocked(ev); err != nil {
		return nil, err
	}
	return res, nil
}

func partialBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
