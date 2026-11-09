package exchange_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/domain"
)

// 로드맵 19 지시서 080 4장: 교환 거부·성공 경로의 감사 이벤트를 스냅샷으로 고정하는 합격선.
// 시각·해시·jti·stage 는 제외한다. UPDATE_GOLDEN=1 로 다시 뜨되, 리팩터링 중에는 쓰지 않는다.

const goldenPath = "testdata/exchange_audit_golden.json"

type fakeSnaps struct {
	snap *domain.SubjectSnapshot
	err  error
}

func (f fakeSnaps) GetSubjectSnapshot(context.Context, string) (*domain.SubjectSnapshot, error) {
	return f.snap, f.err
}

type failingIssuer struct{ calls int }

func (f *failingIssuer) IssueToken(token.IssueRequest, token.IssueOptions, domain.AuditContext) (*token.IssueResult, error) {
	f.calls++
	return nil, errors.New("issuer down")
}

func normalize(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range x {
			lk := strings.ToLower(k)
			switch {
			case k == "stage" || k == "timestamp" || strings.Contains(lk, "hash"):
				continue
			case strings.Contains(lk, "jti") || strings.Contains(lk, "kid") || strings.Contains(lk, "expires") || strings.Contains(lk, "issued") || lk == "nbf" || lk == "exp" || lk == "iat":
				if s, ok := val.(string); ok && s == "" {
					out[k] = ""
				} else {
					out[k] = "<x>"
				}
			case lk == "trace_id" && autoTrace(val):
				out[k] = "<auto>"
			default:
				out[k] = normalize(val)
			}
		}
		return out
	case []interface{}:
		for i := range x {
			x[i] = normalize(x[i])
		}
		return x
	}
	return v
}

func autoTrace(v interface{}) bool {
	s, _ := v.(string)
	return len(s) > 12 && strings.HasPrefix(s, "trace-1")
}

func readEvents(t *testing.T, path string) []interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []interface{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if a, _ := m["action"].(string); strings.HasPrefix(a, "token.") {
			out = append(out, normalize(m))
		}
	}
	return out
}

func exReq(parent, sub string, b *domain.Budget) exchange.ExchangeRequest {
	return exchange.ExchangeRequest{
		ClientID: "client-subagent", ClientSecret: "subagent-secret-key-02",
		ParentToken: parent, ChildSubject: sub, Scope: "file:read:docs/a.txt",
		TTL: 30 * time.Minute, Budget: b,
	}
}

func snapCases() map[string]func(t *testing.T) *budgetEnv {
	trace := domain.AuditContext{TraceID: "trace-snap", Actor: "snap"}
	run := func(f func(t *testing.T, e *budgetEnv) error) func(t *testing.T) *budgetEnv {
		return func(t *testing.T) *budgetEnv {
			e := newBudgetEnv(t, true, true)
			_ = f(t, e)
			return e
		}
	}
	plain := func(e *budgetEnv, t *testing.T) string { return e.root(t, nil).TokenString }
	ex := func(e *budgetEnv, req exchange.ExchangeRequest) error {
		_, err := e.svc.Exchange(context.Background(), req, trace)
		return err
	}
	withSnaps := func(e *budgetEnv, sp domain.SnapshotProvider) *exchange.ExchangeService {
		s, err := exchange.NewExchangeService(e.issuer, e.verifier, token.NewInMemoryClientRegistry(), nil, e.aw, e.clk,
			exchange.WithBudgetLedger(e.ledger), exchange.WithSnapshotProvider(sp))
		if err != nil {
			panic(err)
		}
		return s
	}
	return map[string]func(t *testing.T) *budgetEnv{
		"client_auth": run(func(t *testing.T, e *budgetEnv) error {
			r := exReq("x", "worker-01", nil)
			r.ClientSecret = "bad"
			return ex(e, r)
		}),
		"subject_empty": run(func(t *testing.T, e *budgetEnv) error { return ex(e, exReq("x", "", nil)) }),
		"subject_not_allowed": run(func(t *testing.T, e *budgetEnv) error {
			return ex(e, exReq("x", "someone-else", nil))
		}),
		"parent_token": run(func(t *testing.T, e *budgetEnv) error { return ex(e, exReq("garbage", "worker-01", nil)) }),
		"lineage_snapshot_error": run(func(t *testing.T, e *budgetEnv) error {
			_, err := withSnaps(e, fakeSnaps{err: errors.New("pip down")}).Exchange(context.Background(), exReq(plain(e, t), "worker-01", nil), trace)
			return err
		}),
		"lineage_epoch_mismatch": run(func(t *testing.T, e *budgetEnv) error {
			_, err := withSnaps(e, fakeSnaps{snap: &domain.SubjectSnapshot{CurrentEpoch: 5}}).Exchange(context.Background(), exReq(plain(e, t), "worker-01", nil), trace)
			return err
		}),
		"downscope": run(func(t *testing.T, e *budgetEnv) error {
			r := exReq(plain(e, t), "worker-01", nil)
			r.Scope = "file:write:docs/zzz.txt"
			return ex(e, r)
		}),
		"budget_downscope_static": run(func(t *testing.T, e *budgetEnv) error {
			r := e.root(t, &domain.Budget{MaxCalls: 2})
			return ex(e, exReq(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 9}))
		}),
		"budget_no_ledger": func(t *testing.T) *budgetEnv {
			e := newBudgetEnv(t, false, true)
			r := e.root(t, &domain.Budget{MaxCalls: 3})
			_ = ex(e, exReq(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 1}))
			return e
		},
		"budget_reserve_fail": run(func(t *testing.T, e *budgetEnv) error {
			r := e.root(t, &domain.Budget{MaxCalls: 4})
			if err := ex(e, exReq(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 3})); err != nil {
				t.Fatal(err)
			}
			return ex(e, exReq(r.TokenString, "worker-02", &domain.Budget{MaxCalls: 3}))
		}),
		"token_issue_fail": run(func(t *testing.T, e *budgetEnv) error {
			svc, err := exchange.NewExchangeService(&failingIssuer{}, e.verifier, token.NewInMemoryClientRegistry(), nil, e.aw, e.clk)
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.Exchange(context.Background(), exReq(plain(e, t), "worker-01", nil), trace)
			return err
		}),
		"success_plain": run(func(t *testing.T, e *budgetEnv) error { return ex(e, exReq(plain(e, t), "worker-01", nil)) }),
		"success_budget": run(func(t *testing.T, e *budgetEnv) error {
			r := e.root(t, &domain.Budget{MaxCalls: 4})
			return ex(e, exReq(r.TokenString, "worker-01", &domain.Budget{MaxCalls: 2}))
		}),
	}
}

func TestExchange_AuditSnapshotUnchanged(t *testing.T) { // TC-080-02
	got := map[string][]interface{}{}
	for name, mk := range snapCases() {
		e := mk(t)
		got[name] = readEvents(t, e.auditP)
	}
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(goldenPath, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]interface{}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for name := range want {
		if !reflect.DeepEqual(got[name], want[name]) {
			g, _ := json.MarshalIndent(got[name], "", " ")
			w, _ := json.MarshalIndent(want[name], "", " ")
			t.Errorf("%s: 감사 이벤트가 착수 전과 다르다\n got: %s\nwant: %s", name, g, w)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("cases %d != golden %d", len(got), len(want))
	}
}

func rawEvents(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]interface{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}
