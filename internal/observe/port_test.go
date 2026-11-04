package observe_test

import (
	"context"
	"errors"
	"testing"

	"authz-harness/internal/domain"
	"authz-harness/internal/observe"
)

type panicObserver struct{}

func (panicObserver) OnStageStart(context.Context, string, string, ...observe.Attr) { panic("boom") }
func (panicObserver) OnStageEnd(context.Context, string, string, bool, ...observe.Attr) {
	panic("boom")
}
func (panicObserver) OnExecutionEnd(context.Context, string, bool, ...observe.Attr) { panic("boom") }
func (panicObserver) OnError(context.Context, string, string, ...observe.Attr)      { panic("boom") }

func TestWrapSafe_SwallowsPanics(t *testing.T) {
	ctx := context.Background()
	o := observe.WrapSafe(panicObserver{})
	o.OnStageStart(ctx, "t", "s")
	o.OnStageEnd(ctx, "t", "s", true)
	o.OnExecutionEnd(ctx, "t", false)
	o.OnError(ctx, "t", "m")
}

func TestWrapSafe_NilAndIdempotent(t *testing.T) {
	if _, ok := observe.WrapSafe(nil).(observe.NoopObserver); !ok {
		t.Fatal("nil must become NoopObserver")
	}
	w := observe.WrapSafe(panicObserver{})
	if observe.WrapSafe(w) != w {
		t.Fatal("already wrapped observer must not be wrapped again")
	}
}

func TestSanitizeAttrs(t *testing.T) {
	full := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
	cut := "eyJhbGciOiJFZERTQSJ9.eyJzdWIi"
	in := []observe.Attr{
		{Key: "a", Value: "x " + full},
		{Key: "b", Value: cut},
		{Key: "error", Value: errors.New("bad " + full)},
		{Key: "n", Value: 7},
	}
	out := observe.SanitizeAttrs(in)
	for _, a := range out[:3] {
		s, ok := a.Value.(string)
		if !ok || domain.ContainsRawToken(s) || s == "" {
			t.Fatalf("attr %s not sanitized: %v", a.Key, a.Value)
		}
	}
	if out[3].Value != 7 {
		t.Fatal("non-string value must be preserved")
	}
	if in[0].Value.(string) != "x "+full {
		t.Fatal("input slice must not be mutated")
	}
}
