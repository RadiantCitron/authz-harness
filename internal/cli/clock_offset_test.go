package cli

import (
	"testing"
	"time"
)

// parseNonNegativeClockOffset 의 경계를 직접 고정한다(계획 044).
// 기대값은 「0 오프셋은 유효하고 음수만 거부한다」는 요구사항과 time.ParseDuration 규칙에서 도출했다.
func TestParseNonNegativeClockOffset(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"빈 값은 미지정", "", 0, false},
		{"공백만도 미지정", "   ", 0, false},
		{"0s 는 유효한 0 오프셋", "0s", 0, false},
		{"단위 없는 0 도 유효", "0", 0, false},
		{"음의 영(-0s)은 0", "-0s", 0, false},
		{"1ns 는 허용(가장 작은 양수)", "1ns", time.Nanosecond, false},
		{"10s", "10s", 10 * time.Second, false},
		{"2h", "2h", 2 * time.Hour, false},
		{"-1ns 는 거부(가장 작은 음수)", "-1ns", 0, true},
		{"-10m 은 거부", "-10m", 0, true},
		{"형식 오류 abc", "abc", 0, true},
		{"단위 없는 비영 숫자는 형식 오류", "10", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNonNegativeClockOffset(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseNonNegativeClockOffset(%q) err = %v, wantErr %v", tc.raw, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("parseNonNegativeClockOffset(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
