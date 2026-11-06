package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/domain"
)

func mkEv(i int, ver int, arg, res string) Event {
	return Event{
		SchemaVersion: ver, Timestamp: time.Date(2026, 11, 4, 10, 0, i, 0, time.UTC),
		TraceID: "t", Actor: "a", AgentID: "agent", Action: "x", Resource: "r", Decision: "allow",
		Reason: "AUTHORIZED", TokenJTI: "jti", ArgHash: arg, ResultHash: res, Success: true,
	}
}

// chain 은 지정한 버전의 레코드들을 정상 해시로 연결해 JSONL 줄로 만든다.
func chain(evs ...Event) []Event {
	prev := ""
	for i := range evs {
		evs[i].PrevHash = prev
		evs[i].CurrHash = ComputeEventHash(prev, evs[i])
		prev = evs[i].CurrHash
	}
	return evs
}

func writeLines(t *testing.T, evs []Event) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	var sb strings.Builder
	for _, e := range evs {
		b, _ := json.Marshal(e)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func wantBroken(t *testing.T, err error) {
	t.Helper()
	if domain.ReasonFromError(err, "") != domain.ReasonAuditIntegrityBroken {
		t.Fatalf("want integrity broken, got %v", err)
	}
}

func TestSchemaCompat_V1FixtureValid(t *testing.T) { // TC-030-01
	p := writeLines(t, chain(mkEv(1, 0, "", ""), mkEv(2, 0, "", ""), mkEv(3, 1, "", "")))
	if err := VerifyHashChain(p); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaCompat_AppendV2AfterV1(t *testing.T) { // TC-030-02
	p := writeLines(t, chain(mkEv(1, 0, "", ""), mkEv(2, 0, "", ""), mkEv(3, 0, "", "")))
	w, err := NewJSONLWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 4; i <= 5; i++ {
		if err := w.Log(mkEv(i, 0, "sha256:aa", "")); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	if err := VerifyHashChain(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if strings.Count(string(b), `"schema_version":4`) != 2 || strings.Contains(lines[2], "schema_version") {
		t.Fatalf("unexpected versions:\n%s", b)
	}
}

func TestSchemaCompat_V2FieldTamper(t *testing.T) { // TC-030-03
	for _, field := range []string{"arg_hash", "result_hash", "token_jti", "agent_id"} {
		t.Run(field, func(t *testing.T) {
			p := writeLines(t, chain(mkEv(1, 2, "sha256:aaaa", "sha256:bbbb")))
			b, _ := os.ReadFile(p)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			m[field] = m[field].(string) + "x"
			nb, _ := json.Marshal(m)
			_ = os.WriteFile(p, append(nb, '\n'), 0o600)
			wantBroken(t, VerifyHashChain(p))
		})
	}
}

func TestSchemaCompat_V2FieldInjectedIntoV1(t *testing.T) { // TC-030-04
	p := writeLines(t, chain(mkEv(1, 0, "", "")))
	b, _ := os.ReadFile(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["arg_hash"] = "sha256:aaaa"
	nb, _ := json.Marshal(m)
	_ = os.WriteFile(p, append(nb, '\n'), 0o600)
	wantBroken(t, VerifyHashChain(p))
}

func TestSchemaCompat_UnknownVersionAndDowngrade(t *testing.T) { // TC-030-05
	wantBroken(t, VerifyHashChain(writeLines(t, chain(mkEv(1, 5, "", "")))))
	wantBroken(t, VerifyHashChain(writeLines(t, chain(mkEv(1, 2, "", ""), mkEv(2, 0, "", "")))))
}
