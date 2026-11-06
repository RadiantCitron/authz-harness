package ui

import (
	"io"

	"authz-harness/internal/harness"
)

// OutputFormat 은 UI 출력 포맷 식별자다.
type OutputFormat string

const (
	FormatSummary OutputFormat = "summary"
	FormatExplain OutputFormat = "explain"
	FormatJSON    OutputFormat = "json"
)

// Formatter 는 하네스 실행 결과를 사용자 또는 기계에 표현하는 인터페이스다.
type Formatter interface {
	Format(results []harness.ScenarioResult) error
}

// SummaryFormatter 는 콘솔 테이블 요약 뷰 포매터다.
type SummaryFormatter struct {
	out io.Writer
}

// NewSummaryFormatter 는 SummaryFormatter 를 생성한다.
func NewSummaryFormatter(out io.Writer) *SummaryFormatter {
	return &SummaryFormatter{out: out}
}

// ExplainFormatter 는 초보자용 단계 파이프라인 상태도 및 역설 해설 포매터다.
type ExplainFormatter struct {
	out io.Writer
}

// NewExplainFormatter 는 ExplainFormatter 를 생성한다.
func NewExplainFormatter(out io.Writer) *ExplainFormatter {
	return &ExplainFormatter{out: out}
}

// JSONFormatter 는 표준 기계 판독 JSON 포매터다.
type JSONFormatter struct {
	out io.Writer
}

// NewJSONFormatter 는 JSONFormatter 를 생성한다.
func NewJSONFormatter(out io.Writer) *JSONFormatter {
	return &JSONFormatter{out: out}
}
