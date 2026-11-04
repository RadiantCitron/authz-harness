package catalog

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/audit/checkpoint"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/observe"
)

// G13: 감사 확장 및 관측성 포트 (E2E-61 ~ E2E-66)
func g13Scenarios() []harness.Scenario {
	return []harness.Scenario{
		newG13Tamper("E2E-61", "꼬리 절단 적발", "체인은 유효하지만 서명 체크포인트보다 기록이 짧아진 것을 적발한다.",
			"AuditTailTruncation", "마지막 감사 줄을 잘라 내도 해시 체인은 유효하지만, 서명 체크포인트가 절단을 적발했습니다.", g13Truncate),
		newG13Tamper("E2E-62", "전체 재작성 적발", "공격자가 해시를 모두 재계산해 체인이 유효해도 서명 체크포인트가 재작성을 적발한다.",
			"AuditFullRewrite", "해시를 처음부터 다시 계산한 위조 체인도 서명 체크포인트와 맞지 않아 적발됐습니다.", g13Rewrite),
		newG13Tamper("E2E-63", "체크포인트 검증 재료 부재 Fail-Closed", "검증용 공개키가 없으면 통과가 아니라 거부한다.",
			"AuditCheckpointMaterialMissing", "검증 재료(공개키)가 없어 체크포인트를 확인할 수 없으면 통과가 아니라 거부했습니다.", g13DeletePub),
		&g13Payload{},
		&g13PanicObs{},
		&g13Mixed{},
	}
}

func g13Paths(env *harness.SandboxEnvironment) (priv, pub, ckpt string) {
	return filepath.Join(filepath.Dir(env.PrivKeyPath), "audit_signing_key.priv.json"),
		filepath.Join(filepath.Dir(env.PubJWKSPath), "audit_verification_key.pub.json"),
		filepath.Join(filepath.Dir(env.PubJWKSPath), "audit_checkpoint.json")
}

func g13Meta(id, name, desc, attack, explain string, exit domain.ExitCode, file harness.FileExpectation) harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID: id, Group: "G13", Name: name, Description: desc, AttackClass: attack, ParadoxExplanation: explain,
		Expected: harness.ExpectedAssertion{
			ExitCode: exit,
			File:     file,
			Audit: harness.AuditExpectation{
				RequireEvent: true, ExpectedAction: "pep.allow", ExpectedDecision: "allow", ExpectedReason: domain.ReasonAuthorized,
			},
			HashChain: harness.HashChainExpectation{RequireValidChain: true, NoRawTokenLeak: true},
		},
	}
}

func g13Prepare(ctx context.Context, env *harness.SandboxEnvironment, resource, scope string) (string, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return "", err
	}
	defer stack.Close()
	for _, a := range []domain.Action{domain.ActionFileWrite, domain.ActionFileRead} {
		if _, err := grantPermission(ctx, stack, "worker-01", a, resource); err != nil {
			return "", err
		}
	}
	return issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", scope, 10*time.Minute, token.IssueOptions{})
}

// ---- E2E-61~63: 체크포인트 사후 검증 ----

type g13Tamper struct {
	meta   harness.ScenarioMetadata
	tamper func(env *harness.SandboxEnvironment) error
	token  string
}

func newG13Tamper(id, name, desc, attack, explain string, tamper func(*harness.SandboxEnvironment) error) *g13Tamper {
	return &g13Tamper{
		meta: g13Meta(id, name, desc, attack, explain, domain.ExitAuditFailure,
			harness.FileExpectation{RelPath: "g13_tamper.txt", ExpectExist: true, ExpectedContent: "g13 payload"}),
		tamper: tamper,
	}
}

func (s *g13Tamper) Metadata() harness.ScenarioMetadata { return s.meta }

func (s *g13Tamper) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	tok, err := g13Prepare(ctx, env, "g13_tamper.txt", "file:write")
	s.token = tok
	return err
}

func (s *g13Tamper) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	res, err := stack.PEP.Execute(ctx, pep.Request{
		Token: s.token, Action: domain.ActionFileWrite, Resource: "g13_tamper.txt", Data: []byte("g13 payload"), TraceID: "trace-" + s.meta.ID,
	})
	_ = stack.Close()
	if err != nil {
		return domain.ExitInternalError, err
	}
	if !res.Allowed {
		return res.ExitCode, nil
	}
	priv, pub, ckpt := g13Paths(env)
	if _, err := checkpoint.Create(env.AuditPath, priv, pub, ckpt, env.MockClock); err != nil {
		return domain.ExitInternalError, err
	}
	if err := s.tamper(env); err != nil {
		return domain.ExitInternalError, err
	}
	return domain.ExitCodeFromError(checkpoint.Verify(env.AuditPath, ckpt, pub), domain.ExitSuccess), nil
}

func g13ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}

func g13Truncate(env *harness.SandboxEnvironment) error {
	lines, err := g13ReadLines(env.AuditPath)
	if err != nil || len(lines) < 2 {
		return fmt.Errorf("truncate: need >=2 records: %v", err)
	}
	return os.WriteFile(env.AuditPath, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600)
}

func g13Rewrite(env *harness.SandboxEnvironment) error {
	lines, err := g13ReadLines(env.AuditPath)
	if err != nil || len(lines) == 0 {
		return fmt.Errorf("rewrite: no records: %v", err)
	}
	prev := ""
	for i, l := range lines {
		var ev audit.Event
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			return err
		}
		if i == 0 {
			ev.Resource = "tampered-by-attacker"
		}
		ev.PrevHash = prev
		ev.CurrHash = audit.ComputeEventHash(prev, ev) // 공격자도 공식을 안다
		if ev.Metadata != nil {
			ev.Metadata["prev_hash"] = ev.PrevHash
			ev.Metadata["curr_hash"] = ev.CurrHash
		}
		prev = ev.CurrHash
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		lines[i] = string(b)
	}
	return os.WriteFile(env.AuditPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func g13DeletePub(env *harness.SandboxEnvironment) error {
	_, pub, _ := g13Paths(env)
	return os.Remove(pub)
}

// ---- E2E-64: 지문 기록, 원문 비노출 ----

type g13Payload struct{ writeToken, readToken string }

const g13Secret = "G13_SECRET_PAYLOAD"

func (s *g13Payload) Metadata() harness.ScenarioMetadata {
	return g13Meta("E2E-64", "인자·결과 지문, 원문 비노출", "감사에는 인자·결과의 SHA-256 지문만 남고 평문은 남지 않는다.",
		"AuditPlaintextLeak", "감사 로그에는 평문 대신 인자·결과의 지문만 남았습니다.", domain.ExitSuccess,
		harness.FileExpectation{RelPath: "g13_payload.txt", ExpectExist: true, ExpectedContent: g13Secret})
}

func (s *g13Payload) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	// 일반 토큰은 1회용(replay 차단)이므로 쓰기·읽기 토큰을 따로 발급한다.
	w, err := g13Prepare(ctx, env, "g13_payload.txt", "file:write")
	if err != nil {
		return err
	}
	stack, err := setupHarnessStack(env)
	if err != nil {
		return err
	}
	defer stack.Close()
	r, err := issueTestToken(stack, "client-subagent", "subagent-secret-key-02", "worker-01", "file:read", 10*time.Minute, token.IssueOptions{})
	s.writeToken, s.readToken = w, r
	return err
}

func (s *g13Payload) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	for _, rq := range []pep.Request{
		{Token: s.writeToken, Action: domain.ActionFileWrite, Resource: "g13_payload.txt", Data: []byte(g13Secret), TraceID: "trace-e2e-64-w"},
		{Token: s.readToken, Action: domain.ActionFileRead, Resource: "g13_payload.txt", TraceID: "trace-e2e-64-r"},
	} {
		res, err := stack.PEP.Execute(ctx, rq)
		if err != nil {
			return domain.ExitInternalError, err
		}
		if !res.Allowed {
			return res.ExitCode, nil
		}
	}
	_ = stack.Close()

	raw, err := os.ReadFile(env.AuditPath)
	if err != nil {
		return domain.ExitInternalError, err
	}
	if strings.Contains(string(raw), g13Secret) {
		return domain.ExitInternalError, fmt.Errorf("plaintext payload leaked into audit log")
	}
	want := domain.DataDigest([]byte(g13Secret))
	argOK, resultOK := false, false
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var ev audit.Event
		if json.Unmarshal([]byte(l), &ev) != nil {
			continue
		}
		argOK = argOK || (ev.ArgHash == want && ev.TraceID == "trace-e2e-64-w")
		resultOK = resultOK || (ev.ResultHash == want && ev.TraceID == "trace-e2e-64-r")
	}
	if !argOK || !resultOK {
		return domain.ExitInternalError, fmt.Errorf("digest mismatch: arg_hash=%v result_hash=%v", argOK, resultOK)
	}
	return domain.ExitSuccess, nil
}

// ---- E2E-65: 관측성 포트 장애 격리 ----

type g13PanicObserver struct{}

func (g13PanicObserver) OnStageStart(context.Context, string, string, ...observe.Attr) {
	panic("observer down")
}
func (g13PanicObserver) OnStageEnd(context.Context, string, string, bool, ...observe.Attr) {
	panic("observer down")
}
func (g13PanicObserver) OnExecutionEnd(context.Context, string, bool, ...observe.Attr) {
	panic("observer down")
}
func (g13PanicObserver) OnError(context.Context, string, string, ...observe.Attr) {
	panic("observer down")
}

type g13PanicObs struct{ token string }

func (s *g13PanicObs) Metadata() harness.ScenarioMetadata {
	return g13Meta("E2E-65", "관측성 포트 장애 격리", "관측성 포트가 모든 호출에서 panic해도 판정과 감사는 그대로다.",
		"ObservabilityFailure", "텔레메트리 장애가 인가 판정과 Fail-Closed 감사를 바꾸지 못했습니다.", domain.ExitSuccess,
		harness.FileExpectation{RelPath: "g13_obs.txt", ExpectExist: true, ExpectedContent: "observable"})
}

func (s *g13PanicObs) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	tok, err := g13Prepare(ctx, env, "g13_obs.txt", "file:read")
	if err != nil {
		return err
	}
	s.token = tok
	return os.WriteFile(filepath.Join(env.WorkspaceDir, "g13_obs.txt"), []byte("observable"), 0o600)
}

func (s *g13PanicObs) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStackWithObserver(env, env.MockClock, g13PanicObserver{})
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()
	res, err := stack.PEP.Execute(ctx, pep.Request{Token: s.token, Action: domain.ActionFileRead, Resource: "g13_obs.txt", TraceID: "trace-e2e-65"})
	if err != nil {
		return domain.ExitInternalError, err
	}
	return res.ExitCode, nil
}

// ---- E2E-66: v1·v2 혼합 체인 ----

type g13Mixed struct{ token string }

func (s *g13Mixed) Metadata() harness.ScenarioMetadata {
	return g13Meta("E2E-66", "v1·v2 혼합 체인 하위 호환", "v1 레코드 뒤에 v2 레코드가 이어져도 한 체인으로 VALID다.",
		"AuditSchemaCompat", "기존 v1 감사 기록 뒤에 v2 기록이 이어져도 체인은 유효합니다.", domain.ExitSuccess,
		harness.FileExpectation{RelPath: "g13_mixed.txt", ExpectExist: true, ExpectedContent: "mixed"})
}

func (s *g13Mixed) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	// 스택(= 감사 writer)이 만들어지기 전에 v1 픽스처를 먼저 깐다.
	var sb strings.Builder
	prev := ""
	for i := 0; i < 3; i++ {
		ev := audit.Event{
			Timestamp: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC), TraceID: "legacy-v1", Actor: "legacy", Action: "legacy.op",
			Resource: "r", Decision: "allow", Reason: string(domain.ReasonAuthorized), Success: true,
		}
		ev.PrevHash = prev
		ev.CurrHash = audit.ComputeEventHash(prev, ev) // SchemaVersion 0 = v1 공식
		prev = ev.CurrHash
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(env.AuditPath, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	tok, err := g13Prepare(ctx, env, "g13_mixed.txt", "file:write")
	s.token = tok
	return err
}

func (s *g13Mixed) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	res, err := stack.PEP.Execute(ctx, pep.Request{Token: s.token, Action: domain.ActionFileWrite, Resource: "g13_mixed.txt", Data: []byte("mixed"), TraceID: "trace-e2e-66"})
	_ = stack.Close()
	if err != nil {
		return domain.ExitInternalError, err
	}
	if !res.Allowed {
		return res.ExitCode, nil
	}
	lines, err := g13ReadLines(env.AuditPath)
	if err != nil || len(lines) < 4 {
		return domain.ExitInternalError, fmt.Errorf("expected v1 fixture + v2 records: %v", err)
	}
	var first, last audit.Event
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	if first.SchemaVersion >= 2 || last.SchemaVersion != audit.CurrentSchemaVersion {
		return domain.ExitInternalError, fmt.Errorf("unexpected versions first=%d last=%d", first.SchemaVersion, last.SchemaVersion)
	}
	return res.ExitCode, nil
}
