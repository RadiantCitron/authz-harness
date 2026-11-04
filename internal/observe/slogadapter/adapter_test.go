package slogadapter_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/observe"
	"authz-harness/internal/observe/slogadapter"
)

func TestAdapter_MessagesLevelsAndRedaction(t *testing.T) {
	var buf strings.Builder
	o := slogadapter.New(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ctx := context.Background()
	full := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
	cut := "eyJhbGciOiJFZERTQSJ9.eyJzdWIi"

	o.OnStageStart(ctx, "trc", "stage1", observe.Attr{Key: "resource", Value: "a.txt"})
	o.OnStageEnd(ctx, "trc", "stage1", true, observe.Attr{Key: "duration_ms", Value: int64(3)})
	o.OnStageEnd(ctx, "trc", "stage2", false, observe.Attr{Key: "reason", Value: "x"})
	o.OnExecutionEnd(ctx, "trc", true, observe.Attr{Key: "caller_id", Value: "c1"})
	o.OnExecutionEnd(ctx, "trc", false)
	o.OnError(ctx, "trc", "failed to refund budget", observe.Attr{Key: "error", Value: "e " + full}, observe.Attr{Key: "x", Value: cut})

	out := buf.String()
	for _, want := range []string{
		"pep stage entering", "pep stage passed", "pep stage blocked",
		"pep execution succeeded", "pep execution denied or failed",
		"failed to refund budget", "trace_id=trc", "stage=stage1", "duration_ms=3", "caller_id=c1", "[REDACTED_TOKEN]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	if domain.ContainsRawToken(out) {
		t.Fatalf("raw token leaked:\n%s", out)
	}
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "level=WARN") {
		t.Errorf("levels missing:\n%s", out)
	}
}

func TestAdapter_NilLoggerUsesDefault(t *testing.T) {
	if slogadapter.New(nil) == nil {
		t.Fatal("expected observer")
	}
}
