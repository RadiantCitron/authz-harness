package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event 는 감사 로그(audit.jsonl)에 기록되는 불변의 보안 증거 레코드 스키마를 정의한다.
// ROADMAP.md §15 감사 모델 준수.
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	TraceID     string                 `json:"trace_id"`
	Step        string                 `json:"step,omitempty"`
	Actor       string                 `json:"actor"`
	AgentID     string                 `json:"agent_id,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Resource    string                 `json:"resource,omitempty"`
	Decision    string                 `json:"decision,omitempty"` // allow, deny
	Reason      string                 `json:"reason,omitempty"`
	TokenJTI    string                 `json:"token_jti,omitempty"`
	Success     bool                   `json:"success"`
	ErrorClass  string                 `json:"error_class,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Writer 는 감사 로그를 thread-safe하게 Append-only 방식으로 기록하는 인터페이스다.
type Writer interface {
	Log(event Event) error
	Close() error
}

// JSONLWriter 는 파일에 JSON Lines 형식으로 이벤트를 기록하는 구현체다.
type JSONLWriter struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewJSONLWriter 는 주어진 경로에 감사 로그 파일을 열거나 생성한다.
func NewJSONLWriter(path string) (*JSONLWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit writer: failed to open log file %s: %w", path, err)
	}
	return &JSONLWriter{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// Log 는 단일 감사 이벤트를 한 줄의 JSON으로 기록하고 flush 한다.
func (w *JSONLWriter) Log(event Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	if err := w.enc.Encode(event); err != nil {
		return fmt.Errorf("audit writer: failed to encode event: %w", err)
	}

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
