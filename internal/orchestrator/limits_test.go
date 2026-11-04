package orchestrator

import (
	"errors"
	"testing"
	"time"

	"authz-harness/internal/domain"
)

func TestTC_020_01_NormalizeDefaults(t *testing.T) {
	l, err := Limits{}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if l.Timeout != 10*time.Second || l.WaitDelay != 500*time.Millisecond || l.MaxOutputBytes != 1<<20 {
		t.Fatalf("unexpected defaults: %+v", l)
	}
}

func TestTC_020_02_NormalizeRejectsNegative(t *testing.T) {
	for _, l := range []Limits{{Timeout: -1}, {MaxOutputBytes: -100}, {WaitDelay: -1}} {
		_, err := l.Normalize()
		var de *domain.Error
		if !errors.As(err, &de) || de.ExitCode != domain.ExitBadInput {
			t.Fatalf("limits %+v: want ExitBadInput domain error, got %v", l, err)
		}
	}
}
