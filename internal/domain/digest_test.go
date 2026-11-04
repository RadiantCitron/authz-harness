package domain

import (
	"strings"
	"testing"
)

func TestDataDigest(t *testing.T) { // TC-030-07
	if DataDigest(nil) != "" || DataDigest([]byte{}) != "" {
		t.Fatal("empty input must yield empty digest")
	}
	d := DataDigest([]byte("a"))
	if !strings.HasPrefix(d, "sha256:ca978112ca1bbdca") || len(d) != len("sha256:")+64 {
		t.Fatalf("got %s", d)
	}
}
