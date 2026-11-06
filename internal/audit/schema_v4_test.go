package audit_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"authz-harness/internal/audit"
)

func v4Ev(i int, stage string) audit.Event {
	e := v3Ev(i, 4)
	e.Stage = stage
	return e
}

// TC-050-01: v4 기록의 stage 를 한 글자 고치면 audit verify 가 실패한다.
func TestV4_StageTamperDetected(t *testing.T) {
	p := chainLines(t, v4Ev(1, "boundary"), v4Ev(2, "execute"))
	if err := audit.VerifyHashChain(p); err != nil {
		t.Fatalf("clean v4: %v", err)
	}
	b, _ := os.ReadFile(p)
	tampered := strings.Replace(string(b), `"stage":"execute"`, `"stage":"executa"`, 1)
	if tampered == string(b) {
		t.Fatal("stage field not found in record")
	}
	_ = os.WriteFile(p, []byte(tampered), 0o600)
	broken(t, audit.VerifyHashChain(p))
}

// TC-050-01 보강: stage 를 지우는 변조도 잡는다(빈 값과 값 있음의 해시가 다르다).
func TestV4_StageRemovalDetected(t *testing.T) {
	p := chainLines(t, v4Ev(1, "authz"))
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(strings.Replace(string(b), `"stage":"authz",`, ``, 1)), 0o600)
	broken(t, audit.VerifyHashChain(p))
}

// TC-050-03: v3 뒤에 v4 가 이어진 파일은 통과한다.
func TestV4_MixedAfterV3Valid(t *testing.T) {
	p := chainLines(t, v3Ev(1, 3), v3Ev(2, 3), v4Ev(3, "input"), v4Ev(4, ""))
	if err := audit.VerifyHashChain(p); err != nil {
		t.Fatalf("mixed v3→v4: %v", err)
	}
}

// TC-050-07: 낮은 버전 번호를 단 기록에 stage 를 끼워 넣으면 해시가 맞아도 거부한다.
func TestV4_StageInjectedIntoOlderVersionRejected(t *testing.T) {
	for _, ver := range []int{0, 1, 2, 3} {
		e := v3Ev(1, ver)
		e.Stage = "execute"
		// 해시는 해당 버전 공식으로 맞게 계산되어 있으므로 해시 불일치가 아니라 규칙 위반으로 걸러진다.
		broken(t, audit.VerifyHashChain(chainLines(t, e)))
	}
}

// 해시 입력에 Stage 가 들어 있음: 같은 이벤트라도 단계가 다르면 해시가 다르다. v3 공식은 단계를 보지 않는다.
func TestV4_HashCoversStage(t *testing.T) {
	a, b := v4Ev(1, "authz"), v4Ev(1, "boundary")
	if audit.ComputeEventHash("p", a) == audit.ComputeEventHash("p", b) {
		t.Fatal("v4 hash must cover stage")
	}
	a3, b3 := v3Ev(1, 3), v3Ev(1, 3)
	b3.Stage = "boundary"
	if audit.ComputeEventHash("p", a3) != audit.ComputeEventHash("p", b3) {
		t.Fatal("v3 formula must stay unchanged")
	}
}

// 쓰기 경로: 기록기가 stage 를 최상위 필드로 남긴다.
func TestV4_WriterKeepsStageAtTopLevel(t *testing.T) {
	p := t.TempDir() + "/a.jsonl"
	w, _ := audit.NewJSONLWriter(p)
	if err := w.Log(audit.Event{TraceID: "t", Actor: "a", Action: "pep.deny", Stage: "boundary", Success: false}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	b, _ := os.ReadFile(p)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["stage"] != "boundary" || m["schema_version"] != float64(4) {
		t.Fatalf("record = %s", b)
	}
	if md, _ := m["metadata"].(map[string]any); md["stage"] != nil {
		t.Fatalf("metadata must not carry stage: %v", md)
	}
}
