// Package audit 는 감사 장부의 잘린 꼬리 복구(Tail Recovery) 기능을 제공한다.
//
// [복구 아키텍처 및 무결성 보호 원칙]
// 1. T1 복구 (깨진 불완전 꼬리 격리 - tail_moved):
//   - 프로세스 갑작스러운 비정상 종료(SIGKILL 등)로 인해 마지막 레코드가 쓰이다 말고 불완전한 JSON 조각으로 남았을 때,
//     해당 조각을 삭제하여 인위적으로 덮는 대신 별도의 보존 파일(`.partial-<timestamp>`)로 원자적 이동 보존한다.
//   - 원본 감사 파일은 이전 줄바꿈 위치까지 truncate 한 뒤, 사슬의 연속성을 보존하기 위해 "audit.recovered" 이벤트를 체인에 정식 기록한다.
//
// 2. T2 복구 (온전한 레코드의 줄바꿈 누락 복구 - newline_appended):
//   - 마지막 레코드가 JSON 파싱 및 해시 체인 검증을 통과했으나 마지막 '\n' 만 누락된 경우,
//     레코드를 훼손하지 않고 '\n' 1바이트만 안전하게 덧붙인 뒤 "audit.recovered" 이벤트를 체인에 잇는다.
//
// 3. Fail-Closed 원칙:
//   - 꼬리 외에 파일 중간에 변조나 훼손(INTEGRITY_BROKEN)이 있는 경우 recover 는 절대 수행되지 않고 즉시 거부된다.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

// RecoveryResult 는 RecoverIncompleteTail 의 복구 결과 보고서다.
// Recovered 가 false 면 파일에 복구할 손상이 없었음을 의미한다.
type RecoveryResult struct {
	// Recovered 는 복구 동작이 실제로 수행되었는지 여부다.
	Recovered bool

	// Kind 는 복구 유형이다 ("tail_moved": T1 깨진 조각 격리, "newline_appended": T2 줄바꿈 보강).
	Kind string

	// RecordNumber 는 T2 에서 줄바꿈을 덧붙인 레코드 번호다 (1부터 시작).
	RecordNumber int

	// PartialPath 는 T1 에서 잘린 불완전 꼬리 바이트가 안전하게 격리 보존된 파일 경로다.
	PartialPath string

	// TruncatedBytes 는 잘려 나간 조각의 바이트 수다.
	TruncatedBytes int

	// TruncatedSHA 는 격리된 조각의 SHA-256 해시값이다.
	TruncatedSHA string
}

// RecoverIncompleteTail 은 기록 도중 충돌로 잘린 마지막 줄을 옆 파일로 보존하고 사슬을 복구한다.
// 「잘린 꼬리」(줄바꿈 없이 끝나는 깨진 JSON, 앞 사슬은 온전)가 아니면 아무것도 바꾸지 않고 오류를 반환한다.
// 복구 사실은 audit.recover 이벤트로 사슬에 남는다 (plan-008 W2).
func RecoverIncompleteTail(path string, clock domain.Clock) (*RecoveryResult, error) {
	var res *RecoveryResult
	err := withAuditLock(path, func() error {
		var rerr error
		res, rerr = recoverLocked(path, clock)
		return rerr
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// recoverLocked 는 배타 flock 을 이미 잡은 상태에서 RecoverIncompleteTail 의 본문을 수행한다.
func recoverLocked(path string, clock domain.Clock) (*RecoveryResult, error) {
	verr := VerifyHashChain(path)
	if verr == nil {
		return &RecoveryResult{}, nil
	}
	if !isReason(verr, domain.ReasonAuditTailIncomplete) {
		return nil, verr
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to read audit file: %v", err), err)
	}
	keep := bytes.LastIndexByte(data, '\n') + 1
	partial := data[keep:]
	// VerifyHashChain 이 TAIL_INCOMPLETE 를 낸 꼬리가 JSON 으로 풀리면, 사슬 규칙까지 통과한 T2 다.
	// (규칙 위반이면 INTEGRITY_BROKEN 으로 위에서 이미 거부됐다.)
	if json.Valid(bytes.TrimSpace(partial)) {
		return recoverNewline(path, clock, bytes.Count(data, []byte{'\n'})+1)
	}
	sum := sha256.Sum256(partial)
	res := &RecoveryResult{
		Recovered:      true,
		Kind:           "tail_moved",
		PartialPath:    path + ".partial-" + clock.Now().UTC().Format("20060102T150405.000000000Z"),
		TruncatedBytes: len(partial),
		TruncatedSHA:   hex.EncodeToString(sum[:]),
	}

	if err := storage.AtomicWriteFile(res.PartialPath, partial, 0o600); err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to preserve truncated tail: %v", err), err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to open audit file: %v", err), err)
	}
	if err := f.Truncate(int64(keep)); err != nil {
		f.Close()
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to truncate audit file: %v", err), err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to sync audit file: %v", err), err)
	}
	f.Close()

	w, err := NewJSONLWriter(path)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, err.Error(), err)
	}
	defer w.Close()
	ev := Event{
		Timestamp: clock.Now().UTC().Truncate(time.Nanosecond),
		TraceID:   "audit-recover",
		Actor:     "operator",
		Action:    "audit.recovered",
		Resource:  filepath.Base(res.PartialPath),
		Decision:  "allow",
		Reason:    string(domain.ReasonAuditTailIncomplete),
		Success:   true,
		Metadata: map[string]interface{}{
			"recovery_kind":    "tail_moved",
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

// recoverNewline 은 T2(해시 검증을 통과한 온전한 기록에 줄바꿈만 빠진 꼬리)를 복구한다.
// 기록은 사슬에 그대로 두고 '\n' 한 바이트만 덧붙인 뒤 복구 이벤트를 잇는다 (plan-010 D-01).
// flock 은 호출자가 이미 잡고 있다.
func recoverNewline(path string, clock domain.Clock, recordNo int) (*RecoveryResult, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to open audit file: %v", err), err)
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		f.Close()
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to append newline: %v", err), err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to sync audit file: %v", err), err)
	}
	if err := f.Close(); err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to close audit file: %v", err), err)
	}

	w, err := NewJSONLWriter(path)
	if err != nil {
		return nil, domain.NewError(domain.ReasonAuditLogFailed, err.Error(), err)
	}
	defer w.Close()
	ev := Event{
		Timestamp: clock.Now().UTC().Truncate(time.Nanosecond),
		TraceID:   "audit-recover",
		Actor:     "operator",
		Action:    "audit.recovered",
		Resource:  fmt.Sprintf("newline-appended:#%d", recordNo),
		Decision:  "allow",
		Reason:    string(domain.ReasonAuditTailIncomplete),
		Success:   true,
		Metadata: map[string]interface{}{
			"recovery_kind": "newline_appended",
			"record_number": recordNo,
		},
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.appendLocked(ev); err != nil {
		return nil, err
	}
	return &RecoveryResult{Recovered: true, Kind: "newline_appended", RecordNumber: recordNo}, nil
}
