package harness

import (
	"os"
	"strings"
	"testing"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// 계획 021 S1 — H1~H3(해시·토큰 판정 유지), L1·L2·L4·L5(임시 자원 정리) 인수 시험.

func writeChain(t *testing.T, env *SandboxEnvironment, n int, resource string) {
	t.Helper()
	w, err := audit.NewJSONLWriter(env.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := w.Log(audit.Event{TraceID: "t", Actor: "w", Action: "read", Resource: resource, Decision: "allow", Success: true}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
}

func newEnv(t *testing.T) *SandboxEnvironment {
	t.Helper()
	env, err := NewSandboxEnvironment(SandboxConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Cleanup() })
	return env
}

func evalChain(env *SandboxEnvironment, noLeak bool) AssertionResult {
	return NewDefaultEvaluator().Evaluate(env, domain.ExitSuccess, ExpectedAssertion{
		ExitCode:  domain.ExitSuccess,
		HashChain: HashChainExpectation{RequireValidChain: !noLeak, NoRawTokenLeak: noLeak},
	})
}

// H1: 정상 사슬은 통과, prev_hash 어긋남·내용 변조는 실패.
func TestPlan021_H1_ChainVerdicts(t *testing.T) {
	env := newEnv(t)
	writeChain(t, env, 3, "x")
	if res := evalChain(env, false); !res.Passed || !res.HashChainPassed {
		t.Fatalf("intact chain must pass: %+v", res)
	}
	orig, _ := os.ReadFile(env.AuditPath)
	cases := map[string]string{
		"content tamper": strings.Replace(string(orig), `"actor":"w"`, `"actor":"evil"`, 1),
		"prev_hash skew": strings.Replace(string(orig), `"prev_hash":"`, `"prev_hash":"00`, 2),
	}
	for name, tampered := range cases {
		t.Run(name, func(t *testing.T) {
			if tampered == string(orig) {
				t.Fatal("tamper had no effect")
			}
			if err := os.WriteFile(env.AuditPath, []byte(tampered), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := evalChain(env, false); res.Passed || res.HashChainPassed {
				t.Fatalf("tampered chain must fail: %+v", res)
			}
		})
	}
}

// H2: 기록 0건 + RequireValidChain 은 실패.
func TestPlan021_H2_EmptyFails(t *testing.T) {
	if res := evalChain(newEnv(t), false); res.Passed || res.HashChainPassed {
		t.Fatalf("empty audit must fail: %+v", res)
	}
}

// H3: 원시 토큰이 든 기록은 NoRawTokenLeak 에서 실패.
func TestPlan021_H3_RawTokenLeakFails(t *testing.T) {
	env := newEnv(t)
	writeChain(t, env, 1, "eyJ"+"hbGciOiJFZERTQSJ9."+"eyJ"+"zdWIiOiJ3b3JrZXIifQ."+"c2lnbmF0dXJlLXNpZ25hdHVyZQ")
	if res := evalChain(env, true); res.Passed || res.HashChainPassed {
		t.Fatalf("raw token leak must fail: %+v", res)
	}
}
