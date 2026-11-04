package ui

import (
	"encoding/json"
	"time"

	"authz-harness/internal/harness"
)

// JSONReport 는 run 명령의 기계 판독 JSON 출력 스키마다.
type JSONReport struct {
	Version       string                   `json:"version"`
	Total         int                      `json:"total"`
	Passed        int                      `json:"passed"`
	Skipped       int                      `json:"skipped"`
	Failed        int                      `json:"failed"`
	TotalDuration string                   `json:"total_duration"`
	Results       []harness.ScenarioResult `json:"results"`
}

// Format 은 JSONFormatter 의 Formatter 인터페이스 구현체다.
func (f *JSONFormatter) Format(results []harness.ScenarioResult) error {
	total := len(results)
	passed := 0
	skipped := 0
	var totalDuration time.Duration

	for _, r := range results {
		totalDuration += r.Duration
		if r.Skipped {
			skipped++
		} else if r.Passed {
			passed++
		}
	}

	report := JSONReport{
		Version:       "0.1.0",
		Total:         total,
		Passed:        passed,
		Skipped:       skipped,
		Failed:        total - passed - skipped,
		TotalDuration: totalDuration.String(),
		Results:       results,
	}

	encoder := json.NewEncoder(f.out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
