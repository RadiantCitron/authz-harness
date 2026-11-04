package slogadapter_test

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/observe/slogadapter"
)

func TestRedactReplaceAttr(t *testing.T) {
	const tok = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
	tests := []struct {
		name     string
		log      func(l *slog.Logger)
		want     []string
		wantNone []string
	}{
		{
			name:     "문자열 속성의 토큰은 치환된다",
			log:      func(l *slog.Logger) { l.Info("m", "output", "raw "+tok) },
			want:     []string{"[REDACTED_TOKEN]", "output="},
			wantNone: []string{tok},
		},
		{
			name:     "error 속성의 토큰은 치환된다",
			log:      func(l *slog.Logger) { l.Error("m", "error", errors.New("write failed: "+tok)) },
			want:     []string{"[REDACTED_TOKEN]", "write failed"},
			wantNone: []string{tok},
		},
		{
			name:     "그룹 안 속성도 치환된다",
			log:      func(l *slog.Logger) { l.Info("m", slog.Group("g", slog.String("k", tok))) },
			want:     []string{"[REDACTED_TOKEN]"},
			wantNone: []string{tok},
		},
		{
			name:     "메시지에 섞인 토큰도 치환된다",
			log:      func(l *slog.Logger) { l.Info("bearer " + tok) },
			want:     []string{"[REDACTED_TOKEN]"},
			wantNone: []string{tok},
		},
		{
			name:     "토큰이 아닌 값은 그대로다",
			log:      func(l *slog.Logger) { l.Info("m", "method", "tools/call", "n", 7, "err", errors.New("plain")) },
			want:     []string{"method=tools/call", "n=7", "err=plain"},
			wantNone: []string{"[REDACTED_TOKEN]"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: slogadapter.RedactReplaceAttr}))
			tc.log(l)
			out := buf.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in %q", w, out)
				}
			}
			for _, n := range tc.wantNone {
				if strings.Contains(out, n) {
					t.Errorf("unexpected %q in %q", n, out)
				}
			}
			if domain.ContainsRawToken(out) {
				t.Errorf("raw token leaked: %q", out)
			}
		})
	}
}
