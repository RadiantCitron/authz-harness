package orchestrator

import "testing"

func TestTC_020_04_BufferAtLimit(t *testing.T) {
	calls := 0
	b := newLimitedBuffer(1024, func() { calls++ })
	if n, err := b.Write(make([]byte, 1024)); n != 1024 || err != nil {
		t.Fatalf("write: %d %v", n, err)
	}
	if b.Exceeded() || b.Len() != 1024 || calls != 0 {
		t.Fatalf("exceeded=%v len=%d calls=%d", b.Exceeded(), b.Len(), calls)
	}
}

func TestTC_020_05_BufferOverLimit(t *testing.T) {
	calls := 0
	b := newLimitedBuffer(1024, func() { calls++ })
	_, err := b.Write(make([]byte, 1025))
	if err == nil {
		t.Fatal("expected error on overflow")
	}
	for i := 0; i < 5; i++ {
		_, _ = b.Write(make([]byte, 64*1024))
	}
	if !b.Exceeded() || calls != 1 || b.Len() > 1024 {
		t.Fatalf("exceeded=%v calls=%d len=%d", b.Exceeded(), calls, b.Len())
	}
}
