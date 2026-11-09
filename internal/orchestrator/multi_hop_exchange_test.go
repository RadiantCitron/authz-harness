package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/audit"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
)

// 계획 020 인수 시험 M1·M3. 기대값은 요구사항에서 도출했다:
//   - M1: 2-Hop 교환도 단일 합성 루트의 교환 서비스를 쓰므로 조상 Epoch 실시간 대조(lineage_epoch)를 받는다.
//   - M3: 교환 실패의 종료 코드는 사유를 따른다(감사 실패 15, 일반 거부 12).

type failingAudit struct{}

func (failingAudit) Log(audit.Event) error { return errors.New("audit down") }
func (failingAudit) Close() error          { return nil }

type hopEnv struct {
	stack     *app.AppStack
	auditPath string
	root      string
	cfg       MultiHopConfig
}

func newHopEnv(t *testing.T) *hopEnv {
	t.Helper()
	dir := t.TempDir()
	workspace := filepath.Join(dir, "ws")
	auditPath := filepath.Join(dir, "audit", "audit.jsonl")
	stack, err := app.BuildStack(app.AppConfig{
		StatePath:    filepath.Join(dir, "state", "state.json"),
		PrivKeyPath:  filepath.Join(dir, "keys", "private.json"),
		PubJWKSPath:  filepath.Join(dir, "keys", "jwks.json"),
		ReplayPath:   filepath.Join(dir, "state", "replay.json"),
		AuditPath:    auditPath,
		WorkspaceDir: workspace,
	})
	if err != nil {
		t.Fatalf("BuildStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	if err := os.WriteFile(filepath.Join(workspace, "hop.txt"), []byte("hop ok"), 0600); err != nil {
		t.Fatalf("write workspace file: %v", err)
	}
	if _, err := stack.PAP.CreateGrant(context.Background(), pap.CreateGrantRequest{
		Subject: "worker-01", Action: domain.ActionFileRead, Resource: "hop.txt",
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	root, err := stack.TokenIssuer.IssueToken(token.IssueRequest{
		ClientID: "client-orchestrator", ClientSecret: "orchestrator-secret-key-01",
		Subject: "orchestrator-root", Scope: "file:read file:write",
		Audience: "authz-harness", TTL: 30 * time.Minute, Epoch: 1,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "t-setup", Actor: "setup", Reason: "token.issue"})
	if err != nil {
		t.Fatalf("issue root token: %v", err)
	}
	return &hopEnv{
		stack: stack, auditPath: auditPath, root: root.TokenString,
		cfg: MultiHopConfig{WorkspaceDir: workspace, AuditPath: auditPath, Audit: stack.AuditWriter, Gateway: stack.PEP},
	}
}

func (e *hopEnv) run(t *testing.T, cfg MultiHopConfig, svc exchange.Service, leadScope, workerScope string) (domain.ExitCode, error) {
	t.Helper()
	spawner, err := NewMultiHopSpawner(cfg)
	if err != nil {
		t.Fatalf("NewMultiHopSpawner: %v", err)
	}
	return spawner.ExecuteMultiHop(context.Background(), MultiHopDelegationRequest{
		TraceID: "trace-mh-020", RootToken: e.root,
		LeadSubject: "lead-01", LeadScope: leadScope,
		WorkerSubject: "worker-01", WorkerScope: workerScope,
		TargetFile: "hop.txt", Action: domain.ActionFileRead,
		Exchange: svc,
	})
}

func auditEvents(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()
	var out []map[string]interface{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var ev map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("parse audit line: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

// M1: 루트 주체의 Epoch 가 올라간 뒤의 2-Hop 위임은 lineage_epoch 단계에서 거부되어야 한다.
func TestMultiHop_LineageEpochEnforced(t *testing.T) {
	e := newHopEnv(t)
	if _, err := e.stack.PAP.BumpEpoch(context.Background(), "orchestrator-root"); err != nil {
		t.Fatalf("BumpEpoch: %v", err)
	}
	exit, err := e.run(t, e.cfg, e.stack.ExchangeService, "file:read file:write", "file:read")
	if err == nil {
		t.Fatalf("stale-epoch root token must not delegate (exit=%d)", exit)
	}
	if got := domain.ReasonFromError(err, ""); got != domain.ReasonSubjectEpochRevoked {
		t.Errorf("reason = %q, want %q (err=%v)", got, domain.ReasonSubjectEpochRevoked, err)
	}
	if exit == domain.ExitSuccess {
		t.Errorf("exit = %d, want non-zero", exit)
	}
	var found bool
	for _, ev := range auditEvents(t, e.auditPath) {
		if ev["action"] == "token.exchange.deny" && ev["stage"] == string(domain.StageLineageEpoch) {
			found = true
		}
	}
	if !found {
		t.Error("audit has no token.exchange.deny at stage lineage_epoch")
	}
}

// M3: 교환 거부의 종료 코드는 사유를 따른다. 일반 스코프 초과는 12, 거부 감사 기록 실패는 15.
func TestMultiHop_ExchangeFailureExitCode(t *testing.T) {
	t.Run("스코프 초과 위임은 12", func(t *testing.T) {
		e := newHopEnv(t)
		exit, err := e.run(t, e.cfg, e.stack.ExchangeService, "file:read", "file:write")
		if err == nil || exit != domain.ExitAuthzDenied {
			t.Fatalf("exit=%d err=%v, want %d with error", exit, err, domain.ExitAuthzDenied)
		}
	})
	t.Run("교환 감사 기록 실패는 15", func(t *testing.T) {
		e := newHopEnv(t)
		// 거부 감사를 쓰지 못하는 교환 서비스(같은 발급기·검증기, 감사기만 실패)를 주입한다.
		failing, err := exchange.NewExchangeService(e.stack.TokenIssuer, e.stack.TokenVerifier, e.stack.ClientReg, nil, failingAudit{}, domain.RealClock{})
		if err != nil {
			t.Fatalf("NewExchangeService failed: %v", err)
		}
		exit, err := e.run(t, e.cfg, failing, "file:read", "file:write")
		if err == nil {
			t.Fatal("audit failure must fail closed")
		}
		if exit != domain.ExitAuditFailure {
			t.Errorf("exit = %d, want %d (AUDIT_LOG_FAILED); err=%v", exit, domain.ExitAuditFailure, err)
		}
	})
}
