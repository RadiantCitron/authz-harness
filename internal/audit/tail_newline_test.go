package audit_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// writeTwoRecords 는 Writer 로 정상 기록 2줄을 쓴 파일 경로를 돌려준다.
func writeTwoRecords(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := audit.NewJSONLWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 2; i++ {
		if err := w.Log(v3Ev(i, 3)); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func dropLastByte(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if b[len(b)-1] != '\n' {
		t.Fatal("fixture must end with newline")
	}
	b = b[:len(b)-1]
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

func wantTailReason(t *testing.T, err error, r domain.Reason) *domain.Error {
	t.Helper()
	de, ok := err.(*domain.Error)
	if !ok || de.Reason != r {
		t.Fatalf("want reason %s, got %v", r, err)
	}
	return de
}

// AT-S1-01: V-01 재현 — 마지막 \n 만 빠진 온전한 기록을 검증이 잡는다.
func TestAT_S1_01_CompleteTailMissingNewlineDetected(t *testing.T) {
	p := writeTwoRecords(t)
	dropLastByte(t, p)
	err := audit.VerifyHashChain(p)
	de := wantTailReason(t, err, domain.ReasonAuditTailIncomplete)
	if !strings.Contains(de.Message, "missing trailing newline") {
		t.Fatalf("message lacks 'missing trailing newline': %v", de)
	}
	if de.ExitCode != domain.ExitAuditFailure {
		t.Fatalf("exit code = %d, want %d", de.ExitCode, domain.ExitAuditFailure)
	}
}

// AT-S1-02: 그 파일에 Log 는 거부하고 파일 바이트는 그대로다.
func TestAT_S1_02_LogRefusesAndLeavesBytesUnchanged(t *testing.T) {
	p := writeTwoRecords(t)
	before := dropLastByte(t, p)
	w, err := audit.NewJSONLWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	wantTailReason(t, w.Log(v3Ev(9, 3)), domain.ReasonAuditTailIncomplete)
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("file bytes changed by refused Log")
	}
}

// AT-S1-03: 줄바꿈 없는 마지막 줄이 해시 불일치면 변조(T3)다.
func TestAT_S1_03_TamperedTailWithoutNewlineIsIntegrityBroken(t *testing.T) {
	p := writeTwoRecords(t)
	b := dropLastByte(t, p)
	idx := bytes.LastIndexByte(b, '\n') + 1
	tail := bytes.Replace(b[idx:], []byte(`"resource":"r"`), []byte(`"resource":"X"`), 1)
	if bytes.Equal(tail, b[idx:]) {
		t.Fatal("fixture mutation did not apply")
	}
	if err := os.WriteFile(p, append(append([]byte{}, b[:idx]...), tail...), 0o600); err != nil {
		t.Fatal(err)
	}
	wantTailReason(t, audit.VerifyHashChain(p), domain.ReasonAuditIntegrityBroken)
}

// AT-S1-04: 기록이 1줄뿐이고 \n 이 없어도 같은 규칙이다.
func TestAT_S1_04_SingleLineWithoutNewline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := audit.NewJSONLWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Log(v3Ev(0, 3)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	dropLastByte(t, p)
	wantTailReason(t, audit.VerifyHashChain(p), domain.ReasonAuditTailIncomplete)
}

// AT-S1-05: 빈 파일·없는 파일·정상 파일은 거짓 양성이 없다.
func TestAT_S1_05_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "none.jsonl")
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"missing": missing, "empty": empty, "normal": writeTwoRecords(t)} {
		if err := audit.VerifyHashChain(p); err != nil {
			t.Fatalf("%s: verify = %v", name, err)
		}
		w, err := audit.NewJSONLWriter(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Log(v3Ev(5, 3)); err != nil {
			t.Fatalf("%s: Log = %v", name, err)
		}
		w.Close()
		if err := audit.VerifyHashChain(p); err != nil {
			t.Fatalf("%s: verify after Log = %v", name, err)
		}
	}
}
