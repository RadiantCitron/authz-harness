package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"authz-harness/internal/domain"
)

// Event 는 감사 로그(audit.jsonl)에 기록되는 불변의 보안 증거 레코드 스키마를 정의한다.
// ROADMAP.md §15 감사 모델 준수.
type Event struct {
	SchemaVersion int                    `json:"schema_version,omitempty"` // 0·1: 레거시 v1, 2: 확장 필드 보호
	Timestamp     time.Time              `json:"timestamp"`
	TraceID       string                 `json:"trace_id"`
	Step          string                 `json:"step,omitempty"`
	Actor         string                 `json:"actor"`
	AgentID       string                 `json:"agent_id,omitempty"`
	Action        string                 `json:"action,omitempty"`
	Resource      string                 `json:"resource,omitempty"`
	Decision      string                 `json:"decision,omitempty"` // allow, deny (소문자 정규화)
	Reason        string                 `json:"reason,omitempty"`   // domain.Reason 문자열 (최상위 필수 승격)
	TokenJTI      string                 `json:"token_jti,omitempty"`
	ArgHash       string                 `json:"arg_hash,omitempty"`    // v2: 도구 인자 지문(domain.DataDigest)
	ResultHash    string                 `json:"result_hash,omitempty"` // v2: 도구 결과 지문(domain.DataDigest)
	Success       bool                   `json:"success"`
	ErrorClass    string                 `json:"error_class,omitempty"`
	PrevHash      string                 `json:"prev_hash,omitempty"`
	CurrHash      string                 `json:"curr_hash,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ComputeEventHash 는 prevHash 와 이벤트의 불변 핵심 필드들을 결정론적으로 결합하여 SHA-256 해시를 계산한다.
// [결정론적 정규화 공식]:
// Go json.Marshal 의 Metadata 역직렬화 시 타입 변환 및 time.Time 나노초 표기 차이로 인한
// False Positive(가짜 변조 탐지)를 원천 차단하기 위해, 해시 입력은 불변 핵심 필드의 고정 구분자(|) 파이프 문자열로 표준화한다.
func ComputeEventHash(prevHash string, ev Event) string {
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

// CurrentSchemaVersion 은 JSONLWriter 가 새로 쓰는 레코드의 스키마 버전이다.
const CurrentSchemaVersion = 2

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
type Writer interface {
	Log(event Event) error
	Close() error
}

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

	readSize := int64(65536)
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
		// 한 줄이 64KB를 초과하는 극단적 경우 전체 읽기 폴백
		allBytes, err := os.ReadFile(f.Name())
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimRight(string(allBytes), "\r\n "), "\n")
		if len(lines) == 0 {
			return nil, nil
		}
		lastLine = strings.TrimSpace(lines[len(lines)-1])
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

// Log 는 단일 감사 이벤트를 정규화하고 해시 체인을 부착하여 한 줄의 JSON으로 기록하고 flush 한다.
func (w *JSONLWriter) Log(event Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", "audit writer is closed", nil)
	}

	// 1. 이벤트 최상위 필드 정규화
	NormalizeEvent(&event)
	event.SchemaVersion = CurrentSchemaVersion // 호출자 값은 덮어쓴다

	// 2. syscall.Flock 배타 락 획득 (다중 프로세스 원자적 동기화)
	lockPath := w.path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to open lock file %s: %v", lockPath, err), err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to acquire flock on %s: %v", lockPath, err), err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	// 3. 파일의 마지막 레코드로부터 prev_hash 추출 (다중 프로세스 체인 연속성 보장)
	prevHash := ""
	lastEv, err := readLastEvent(w.file)
	if err != nil {
		return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("failed to read last event from audit file: %v", err), err)
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
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to marshal audit event: %v", err), err)
	}

	data = append(data, '\n')
	if _, err := w.file.Write(data); err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to write audit event: %v", err), err)
	}

	if err := w.file.Sync(); err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to sync audit file: %v", err), err)
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
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("failed to open audit file %s: %v", path, err), err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var expectedPrevHash string
	lineNum := 0
	prevVersion := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++

		// No Raw Token Leak 검사
		if domain.ContainsRawToken(line) {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("raw token leak detected in audit record #%d", lineNum), nil)
		}

		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("audit record #%d is not valid JSON: %v", lineNum, err), err)
		}

		// 다운그레이드·주입 규칙
		switch {
		case ev.SchemaVersion < 0 || ev.SchemaVersion > 2:
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("audit record #%d has unknown schema_version %d", lineNum, ev.SchemaVersion), nil)
		case ev.SchemaVersion < 2 && (ev.ArgHash != "" || ev.ResultHash != ""):
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("audit record #%d has v2 fields without schema_version 2", lineNum), nil)
		case prevVersion == 2 && ev.SchemaVersion < 2:
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("audit record #%d downgrades schema version after v2", lineNum), nil)
		}
		prevVersion = ev.SchemaVersion

		evPrevHash := ev.PrevHash
		if evPrevHash == "" && ev.Metadata != nil {
			if ph, ok := ev.Metadata["prev_hash"].(string); ok {
				evPrevHash = ph
			}
		}
		evCurrHash := ev.CurrHash
		if evCurrHash == "" && ev.Metadata != nil {
			if ch, ok := ev.Metadata["curr_hash"].(string); ok {
				evCurrHash = ch
			}
		}

		if evCurrHash == "" {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("audit record #%d missing curr_hash", lineNum), nil)
		}

		if evPrevHash != expectedPrevHash {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("prev_hash mismatch at record #%d: expected %q, got %q", lineNum, expectedPrevHash, evPrevHash), nil)
		}

		computedCurrHash := ComputeEventHash(expectedPrevHash, ev)
		if evCurrHash != computedCurrHash {
			return domain.NewError(domain.ReasonAuditIntegrityBroken, "audit", fmt.Sprintf("curr_hash mismatch at record #%d: expected %q, got %q", lineNum, computedCurrHash, evCurrHash), nil)
		}

		expectedPrevHash = evCurrHash
	}

	if err := scanner.Err(); err != nil {
		return domain.NewError(domain.ReasonAuditLogFailed, "audit", fmt.Sprintf("error scanning audit file %s: %v", path, err), err)
	}

	return nil
}
