package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/storage"
)

// Event 는 domain.AuditEvent 의 별칭이다(DIP: 스키마 정의는 도메인에 있다). ROADMAP.md §15 감사 모델 준수.
type Event = domain.AuditEvent

// MaxRecordBytes 는 감사 한 줄(줄바꿈 제외 JSON 바이트)의 상한이다.
// Writer·검증기·체크포인트가 같은 값을 쓴다(plan-008 W4).
const MaxRecordBytes = 1 << 20

// ComputeEventHash 는 prevHash 와 이벤트의 불변 핵심 필드들을 결정론적으로 결합하여 SHA-256 해시를 계산한다.
// [결정론적 정규화 공식]:
// Go json.Marshal 의 Metadata 역직렬화 시 타입 변환 및 time.Time 나노초 표기 차이로 인한
// False Positive(가짜 변조 탐지)를 원천 차단하기 위해, 해시 입력은 불변 핵심 필드의 고정 구분자(|) 파이프 문자열로 표준화한다.
//
// 스키마 v3 부터는 구분자 대신 필드마다 「<바이트 길이>:<값>」을 이어 붙이는 길이 접두 인코딩을 쓴다
// (필드 경계를 옮겨도 해시가 같아지는 모호성 제거, ADR 0006). v0~v2 공식은 기존 파일 검증을 위해 바꾸지 않는다.
func ComputeEventHash(prevHash string, ev Event) string {
	if ev.SchemaVersion >= 4 {
		return computeHashV4(prevHash, ev)
	}
	if ev.SchemaVersion >= 3 {
		return computeHashV3(prevHash, ev)
	}
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%t",
		prevHash,
		ev.Timestamp.UTC().Format(time.RFC3339Nano),
		ev.TraceID,
		ev.Actor,
		ev.Action,
		ev.Resource,
		ev.Decision,
		ev.Reason,
		ev.Success,
	)
	if ev.SchemaVersion == 2 {
		raw += fmt.Sprintf("|v2|%s|%s|%s|%s", ev.TokenJTI, ev.AgentID, ev.ArgHash, ev.ResultHash)
	}
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func computeHashV3(prevHash string, ev Event) string {
	return lengthPrefixedHash("authz-audit-v3", v3Fields(prevHash, ev))
}

// computeHashV4 는 v3 입력에 Stage 를 더한다(ADR 0009). 단계 값을 고치면 해시가 달라져 audit verify 가 잡는다.
func computeHashV4(prevHash string, ev Event) string {
	return lengthPrefixedHash("authz-audit-v4", append(v3Fields(prevHash, ev), ev.Stage))
}

func v3Fields(prevHash string, ev Event) []string {
	return []string{
		prevHash,
		ev.Timestamp.UTC().Format(time.RFC3339Nano),
		ev.TraceID,
		ev.Actor,
		ev.Action,
		ev.Resource,
		ev.Decision,
		ev.Reason,
		strconv.FormatBool(ev.Success),
		ev.TokenJTI,
		ev.AgentID,
		ev.ArgHash,
		ev.ResultHash,
	}
}

func lengthPrefixedHash(domainTag string, fields []string) string {
	var b strings.Builder
	b.WriteString(domainTag)
	for _, f := range fields {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

// CurrentSchemaVersion 은 JSONLWriter 가 새로 쓰는 레코드의 스키마 버전이다.
const CurrentSchemaVersion = 4

// NormalizeEvent 는 감사 이벤트의 최상위 필드를 정규화한다.
func NormalizeEvent(ev *Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = domain.RealClock{}.Now()
	} else {
		ev.Timestamp = ev.Timestamp.UTC()
	}

	// 1. Decision 정규화 ("ALLOW" -> "allow", "DENY" -> "deny")
	if strings.EqualFold(ev.Decision, "ALLOW") {
		ev.Decision = "allow"
	} else if strings.EqualFold(ev.Decision, "DENY") {
		ev.Decision = "deny"
	} else if ev.Decision == "" {
		if ev.Metadata != nil {
			if d, ok := ev.Metadata["decision"].(string); ok && d != "" {
				if strings.EqualFold(d, "ALLOW") {
					ev.Decision = "allow"
				} else if strings.EqualFold(d, "DENY") {
					ev.Decision = "deny"
				} else {
					ev.Decision = strings.ToLower(d)
				}
			}
		}
		if ev.Decision == "" {
			if ev.Success {
				ev.Decision = "allow"
			} else {
				ev.Decision = "deny"
			}
		}
	}

	// 2. Reason 승격 (비어있고 Metadata["reason"]이 있으면 최상위로 승격)
	if ev.Reason == "" && ev.Metadata != nil {
		if r, ok := ev.Metadata["reason"].(string); ok && r != "" {
			ev.Reason = r
		}
	}

	// 3. Action 표준화:
	// PEP 관문 최종 허용/거부 이벤트의 Action이 "pep.file:read" 형태일 경우,
	// Step에 세부 단계를 보존하고 Action은 "pep.allow"(성공 시) 또는 "pep.deny"(실패 시)로 표준화.
	// 토큰 교환 거부 시 "token.exchange.deny"로 표준화.
	if strings.HasPrefix(ev.Action, "pep.") && ev.Action != "pep.allow" && ev.Action != "pep.deny" {
		if ev.Step == "" {
			ev.Step = ev.Action
		}
		if ev.Success {
			ev.Action = "pep.allow"
		} else {
			ev.Action = "pep.deny"
		}
	} else if ev.Action == "authn.exchange_denied" {
		ev.Action = "token.exchange.deny"
	}

	// TokenJTI 승격
	if ev.TokenJTI == "" && ev.Metadata != nil {
		if jti, ok := ev.Metadata["token_jti"].(string); ok && jti != "" {
			ev.TokenJTI = jti
		}
	}
}

// Writer 는 감사 로그를 thread-safe하게 Append-only 방식으로 기록하는 인터페이스다.
type Writer = domain.AuditWriter

// JSONLWriter 는 파일에 JSON Lines 형식으로 이벤트를 기록하는 구현체다.
// syscall.Flock 및 SHA-256 해시 체인을 통해 다중 프로세스/스레드 간 원자적이고 위변조 불가능한 기록을 보장한다.
type JSONLWriter struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	lastHash string
}

// NewJSONLWriter 는 주어진 경로에 감사 로그 파일을 열거나 생성한다.
func NewJSONLWriter(path string) (*JSONLWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit writer: failed to open log file %s: %w", path, err)
	}
	return &JSONLWriter{
		path: path,
		file: f,
	}, nil
}

// readLastEvent 는 파일의 마지막 레코드를 안전하게 읽어 반환한다.
func readLastEvent(f *os.File) (*Event, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size == 0 {
		return nil, nil
	}

	// 줄바꿈 포함 마지막 줄(MaxRecordBytes+1) + 그 앞 줄바꿈 1바이트를 덮는 창.
	readSize := int64(MaxRecordBytes + 2)
	if size < readSize {
		readSize = size
	}

	buf := make([]byte, readSize)
	offset := size - readSize
	if _, err := f.ReadAt(buf, offset); err != nil {
		return nil, err
	}

	trimmed := strings.TrimRight(string(buf), "\r\n ")
	if trimmed == "" {
		return nil, nil
	}

	idx := strings.LastIndex(trimmed, "\n")
	lastLine := trimmed
	if idx != -1 {
		lastLine = strings.TrimSpace(trimmed[idx+1:])
	} else if size > readSize {
		return nil, fmt.Errorf("last audit record exceeds MaxRecordBytes (%d)", MaxRecordBytes)
	}

	if lastLine == "" {
		return nil, nil
	}

	var ev Event
	if err := json.Unmarshal([]byte(lastLine), &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// tailState 는 감사 파일의 크기와, 마지막 바이트가 '\n' 인지를 돌려준다.
// 빈 파일은 「온전」(endsNL=true)으로 본다. Writer 는 언제나 '\n' 으로 끝나는 줄을 쓰므로
// 마지막 바이트가 '\n' 이 아니면 기록 도중 끊긴 꼬리가 있는 것이다(plan-010).
func tailState(f *os.File) (size int64, endsNL bool, err error) {
	stat, err := f.Stat()
	if err != nil {
		return 0, false, err
	}
	size = stat.Size()
	if size == 0 {
		return 0, true, nil
	}
	var b [1]byte
	if _, err := f.ReadAt(b[:], size-1); err != nil {
		return size, false, err
	}
	return size, b[0] == '\n', nil
}

// Log 는 단일 감사 이벤트를 정규화하고 해시 체인을 부착하여 한 줄의 JSON으로 기록하고 flush 한다.
func (w *JSONLWriter) Log(event Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return domain.NewError(domain.ReasonAuditLogFailed, "audit writer is closed", nil)
	}

	// 1. 배타 flock 아래에서 기록 (다중 프로세스 원자적 동기화)
	return withAuditLock(w.path, func() error { return w.appendLocked(event) })
}

// withAuditLock 은 path+".lock" 에 배타 flock 을 잡고 fn 을 실행한다.
// 잠금을 얻지 못한 실패만 AUDIT_LOG_FAILED 로 감싸고, fn 이 낸 오류는 그대로 돌려준다.
func withAuditLock(path string, fn func() error) error {
	var fnErr error
	lockPath := path + ".lock"
	if err := storage.WithFileLock(lockPath, syscall.LOCK_EX, func() error {
		fnErr = fn()
		return nil
	}); err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to lock %s: %v", lockPath, err), err)
	}
	return fnErr
}

// appendLocked 는 배타 flock 을 이미 잡은 상태에서 이벤트 하나를 사슬에 잇는다.
func (w *JSONLWriter) appendLocked(event Event) error {
	// 1. 이벤트 최상위 필드 정규화
	NormalizeEvent(&event)
	event.SchemaVersion = CurrentSchemaVersion // 호출자 값은 덮어쓴다

	// 3. 파일의 마지막 레코드로부터 prev_hash 추출 (다중 프로세스 체인 연속성 보장)
	prevHash := ""
	if _, endsNL, terr := tailState(w.file); terr != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to inspect audit file tail: %v", terr), terr)
	} else if !endsNL {
		// 줄바꿈 없이 끝나는 파일에 이어 쓰면 두 기록이 한 줄로 붙는다. 쓰지 않고 사유만 고른다.
		reason := domain.ReasonAuditTailIncomplete
		verr := VerifyHashChain(w.path)
		if isReason(verr, domain.ReasonAuditIntegrityBroken) {
			reason = domain.ReasonAuditIntegrityBroken
		}
		return domain.NewError(reason, "audit file does not end with newline; run 'audit recover'", verr)
	}
	lastEv, err := readLastEvent(w.file)
	if err != nil {
		reason := domain.ReasonAuditIntegrityBroken
		if verr := VerifyHashChain(w.path); isReason(verr, domain.ReasonAuditTailIncomplete) {
			reason = domain.ReasonAuditTailIncomplete
		}
		return domain.NewError(reason, fmt.Sprintf("failed to read last event from audit file: %v", err), err)
	}
	if lastEv != nil {
		if lastEv.CurrHash != "" {
			prevHash = lastEv.CurrHash
		} else if lastEv.Metadata != nil {
			if ch, ok := lastEv.Metadata["curr_hash"].(string); ok {
				prevHash = ch
			}
		}
	} else if w.lastHash != "" {
		prevHash = w.lastHash
	}

	event.PrevHash = prevHash
	event.CurrHash = ComputeEventHash(prevHash, event)

	// 기존 검증기 및 메타데이터 하위 호환성을 위해 metadata 에도 동기화
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{})
	}
	event.Metadata["prev_hash"] = event.PrevHash
	event.Metadata["curr_hash"] = event.CurrHash

	// 4. JSON 직렬화 및 쓰기
	data, err := json.Marshal(event)
	if err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to marshal audit event: %v", err), err)
	}
	if len(data) > MaxRecordBytes {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("audit record is %d bytes, exceeds MaxRecordBytes %d", len(data), MaxRecordBytes), nil)
	}

	data = append(data, '\n')
	if _, err := w.file.Write(data); err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to write audit event: %v", err), err)
	}

	if err := w.file.Sync(); err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to sync audit file: %v", err), err)
	}

	w.lastHash = event.CurrHash
	return nil
}

// Close 는 감사 로그 파일을 안전하게 닫는다.
func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// VerifyHashChain 은 지정된 JSONL 감사 파일을 처음부터 끝까지 읽어:
// 1) JSON 파싱 가능 여부
// 2) 각 레코드의 PrevHash == 직전 레코드의 CurrHash 일치 여부
// 3) 각 레코드의 CurrHash == ComputeEventHash(PrevHash, ev) 일치 여부
// 4) 원시 JWT 토큰 유출 여부
// 를 검증하고 위반 시 *domain.Error (ReasonAuditIntegrityBroken, ExitAuditFailure=15)를 반환한다.
func VerifyHashChain(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to open audit file %s: %v", path, err), err)
	}
	defer f.Close()

	// 파일이 \n 으로 끝나지 않으면 마지막 조각은 잘린 꼬리다(plan-010, D-03).
	_, endsNL, err := tailState(f)
	if err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("failed to inspect audit file tail %s: %v", path, err), err)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), MaxRecordBytes+1)

	var expectedPrevHash string
	lineNum := 0
	prevVersion := 0

	// check 는 레코드 한 줄을 검증한다. atTail 은 줄바꿈 없이 끝나는 파일의 마지막 조각임을 뜻한다.
	check := func(line string, n int, atTail bool) error {
		// No Raw Token Leak 검사
		if domain.ContainsRawToken(line) {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("raw token leak detected in audit record #%d", n), nil)
		}

		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			if atTail {
				// 앞 레코드는 모두 통과했고, 줄바꿈 없는 마지막 조각만 깨짐 → 기록 도중 충돌(T1).
				return domain.NewError(domain.ReasonAuditTailIncomplete, fmt.Sprintf("audit record #%d is an incomplete tail (no newline, not valid JSON); run 'audit recover'", n), err)
			}
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("audit record #%d is not valid JSON: %v", n, err), err)
		}

		// 다운그레이드·주입 규칙
		switch {
		case ev.SchemaVersion < 0 || ev.SchemaVersion > CurrentSchemaVersion:
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("audit record #%d has unknown schema_version %d", n, ev.SchemaVersion), nil)
		case ev.SchemaVersion < 2 && (ev.ArgHash != "" || ev.ResultHash != ""):
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("audit record #%d has v2 fields without schema_version 2", n), nil)
		case ev.SchemaVersion < 4 && ev.Stage != "":
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("audit record #%d has stage without schema_version 4", n), nil)
		case prevVersion >= 2 && ev.SchemaVersion < prevVersion:
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("audit record #%d downgrades schema version from v%d to v%d", n, prevVersion, ev.SchemaVersion), nil)
		}
		prevVersion = ev.SchemaVersion

		evPrevHash := ev.EffectivePrevHash()
		evCurrHash := ev.EffectiveCurrHash()

		if evCurrHash == "" {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("audit record #%d missing curr_hash", n), nil)
		}

		if evPrevHash != expectedPrevHash {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("prev_hash mismatch at record #%d: expected %q, got %q", n, expectedPrevHash, evPrevHash), nil)
		}

		computedCurrHash := ComputeEventHash(expectedPrevHash, ev)
		if evCurrHash != computedCurrHash {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("curr_hash mismatch at record #%d: expected %q, got %q", n, computedCurrHash, evCurrHash), nil)
		}

		expectedPrevHash = evCurrHash

		if atTail {
			// 해시 검증까지 통과한 온전한 기록이 줄바꿈만 빠진 상태(T2).
			return domain.NewError(domain.ReasonAuditTailIncomplete, fmt.Sprintf("audit record #%d is a complete record missing trailing newline; run 'audit recover'", n), nil)
		}
		return nil
	}

	// 마지막 레코드가 꼬리인지 알려면 한 줄 앞서 읽어야 하므로 직전 줄을 쥐고 있는다.
	var pending string
	havePending := false
	lastTokenBlank := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			lastTokenBlank = true
			continue
		}
		lastTokenBlank = false
		if havePending {
			if err := check(pending, lineNum, false); err != nil {
				return err
			}
		}
		lineNum++
		pending, havePending = line, true
	}
	scanErr := scanner.Err()
	if havePending && (scanErr != nil || endsNL || lastTokenBlank) {
		if err := check(pending, lineNum, false); err != nil {
			return err
		}
		havePending = false
	}
	if scanErr == nil {
		if havePending {
			if err := check(pending, lineNum, true); err != nil {
				return err
			}
		} else if !endsNL {
			// 공백만 남은 꼬리.
			return domain.NewError(domain.ReasonAuditTailIncomplete, "audit file ends without newline after the last record; run 'audit recover'", nil)
		}
	}

	if err := scanErr; err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, fmt.Sprintf("audit record #%d exceeds MaxRecordBytes %d", lineNum+1, MaxRecordBytes), err)
		}
		return domain.NewError(domain.ReasonAuditLogFailed, fmt.Sprintf("error scanning audit file %s: %v", path, err), err)
	}

	return nil
}

func isReason(err error, r domain.Reason) bool {
	var de *domain.Error
	return errors.As(err, &de) && de.Reason == r
}
