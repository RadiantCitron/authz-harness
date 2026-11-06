package catalog

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/confinement"
	"authz-harness/internal/domain"
	"authz-harness/internal/harness"
	"authz-harness/internal/orchestrator"
	"authz-harness/internal/subagent"
)

// confinedHonestScenario 는 격리 하 정직 워커 실측용 시험 전용 시나리오다(로드맵 16 / 055 TC-055-04).
// 정책이 너무 좁아 정상 동작까지 막는 "가짜 차단"이 없음을 확인한다.
type confinedHonestScenario struct {
	hits   atomic.Int32
	diag   string
	result struct {
		readExit, fetchExit int
		readOut, fetchOut   string
	}
}

func (s *confinedHonestScenario) Metadata() harness.ScenarioMetadata {
	return harness.ScenarioMetadata{
		ID: "T-055-04", Group: "T", Name: "격리 하 정직 워커", AttackClass: "none",
		RequiresSubprocess: true, RequiresConfinement: true,
		Expected: harness.ExpectedAssertion{ExitCode: domain.ExitSuccess, Audit: harness.AuditExpectation{ExpectedStage: harness.NoStageRecord}},
	}
}

func (s *confinedHonestScenario) Setup(ctx context.Context, env *harness.SandboxEnvironment) error {
	f, err := os.OpenFile(env.AuditPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func (s *confinedHonestScenario) Execute(ctx context.Context, env *harness.SandboxEnvironment) (domain.ExitCode, error) {
	stack, err := setupHarnessStack(env)
	if err != nil {
		return domain.ExitInternalError, err
	}
	defer stack.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		_, _ = w.Write([]byte("fetched"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	if err := os.WriteFile(filepath.Join(env.WorkspaceDir, "honest.txt"), []byte("hello"), 0o600); err != nil {
		return domain.ExitInternalError, err
	}
	for _, g := range []struct {
		a domain.Action
		r string
	}{{domain.ActionFileRead, "honest.txt"}, {domain.ActionNetFetch, u.Host}} {
		if _, err := stack.PAP.CreateGrant(ctx, pap.CreateGrantRequest{Subject: "worker-01", Action: g.a, Resource: g.r}); err != nil {
			return domain.ExitInternalError, err
		}
	}
	tok := func() string {
		t, err := issueTestToken(stack, "client-orchestrator", "orchestrator-secret-key-01", "worker-01",
			"file:read:honest.txt net:fetch:"+u.Host, time.Hour, token.IssueOptions{})
		if err != nil {
			panic(err)
		}
		return t
	}

	pol := confinement.WorkerPolicy(env.RootDir, env.WorkspaceDir, filepath.Dir(env.StatePath), env.AuditPath)
	pol.AllowConnectPorts = []int{port}
	sp, err := orchestrator.NewSubprocessSpawner(orchestrator.SpawnConfig{
		BinaryPath: env.BinaryPath,
		Args: []string{"subagent", "worker",
			"-workspace", env.WorkspaceDir, "-state-file", env.StatePath, "-pub-jwks-file", env.PubJWKSPath,
			"-replay-file", env.ReplayPath, "-audit-file", env.AuditPath, "-net-allow", u.Host},
		Limits:      orchestrator.Limits{Timeout: 15 * time.Second},
		Audit:       stack.AuditWriter,
		Confiner:    confinement.WithLauncher(confinement.Platform(), env.BinaryPath),
		Confinement: pol,
	})
	if err != nil {
		return domain.ExitInternalError, err
	}
	rd, err := sp.Spawn(ctx, subagent.SubagentRequest{Version: "1.0", TraceID: "t055-read", Token: tok(), Action: "file:read", FilePath: "honest.txt"})
	if err != nil {
		return domain.ExitInternalError, err
	}
	s.result.readExit = rd.ExitCode
	s.diag = rd.StderrRaw + " | " + rd.StdoutRaw
	if rd.Response != nil {
		s.result.readOut = rd.Response.Output
	}
	ft, err := sp.Spawn(ctx, subagent.SubagentRequest{Version: "1.0", TraceID: "t055-fetch", Token: tok(), Action: "net:fetch", FilePath: srv.URL + "/status"})
	if err != nil {
		return domain.ExitInternalError, err
	}
	s.result.fetchExit = ft.ExitCode
	if ft.Response != nil {
		s.result.fetchOut = ft.Response.Output
	}
	_ = net.IPv4zero
	return domain.ExitSuccess, nil
}

// TC-055-04: 격리 하 정직 워커가 file:read 와 허용 포트 net:fetch 를 정상 수행한다.
func TestConfinedHonestWorker_ReadAndFetch(t *testing.T) {
	runner := harness.NewDefaultRunner(harness.WithBaseDir(t.TempDir()))
	sc := &confinedHonestScenario{}
	_ = runner.Register(sc)
	res, err := runner.RunScenario(context.Background(), "T-055-04")
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Skipf("confinement unavailable: %s", res.Error)
	}
	if res.Error != "" {
		t.Fatalf("scenario error: %s", res.Error)
	}
	if sc.result.readExit != 0 || sc.result.readOut != "hello" {
		t.Errorf("confined file:read: exit=%d out=%q diag=%s", sc.result.readExit, sc.result.readOut, sc.diag)
	}
	if sc.result.fetchExit != 0 || sc.result.fetchOut != "fetched" || sc.hits.Load() != 1 {
		t.Errorf("confined net:fetch: exit=%d out=%q hits=%d", sc.result.fetchExit, sc.result.fetchOut, sc.hits.Load())
	}
}
