package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authz-harness/internal/app"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/domain"
)

// TestMultiHop_InProc 는 BinaryPath 가 비어 있는 inproc 경로에서
// 워커 단계가 PEP 판정을 거치는지, 게이트웨이가 없으면 Fail-Closed 로 거부되는지 검증한다.
// 기대값은 구현이 아니라 요구사항(인가 판정 없는 성공 금지, 허가된 읽기는 pep.allow 기록)에서 도출했다.
func TestMultiHop_InProc(t *testing.T) {
	tests := []struct {
		name         string
		withGateway  bool
		grantWorker  bool
		wantExit     domain.ExitCode
		wantErr      bool
		wantAuditHas string // 감사 파일에 반드시 포함되어야 하는 문자열 ("" 이면 검사 안 함)
	}{
		{
			name:        "게이트웨이 없음: 인가 판정 없이 성공하지 않고 거부",
			withGateway: false,
			grantWorker: true,
			wantExit:    domain.ExitInternalError,
			wantErr:     true,
		},
		{
			name:         "게이트웨이 있고 워커 Grant 있음: PEP 허용 및 pep.allow 기록",
			withGateway:  true,
			grantWorker:  true,
			wantExit:     domain.ExitSuccess,
			wantAuditHas: "pep.allow",
		},
		{
			name:        "게이트웨이 있으나 워커 Grant 없음: PEP 가 거부(성공 아님)",
			withGateway: true,
			grantWorker: false,
			wantExit:    domain.ExitAuthzDenied,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			workspace := filepath.Join(dir, "ws")
			auditPath := filepath.Join(dir, "audit", "audit.jsonl")

			stack, err := app.BuildStack(app.AppConfig{
				StatePath:    filepath.Join(dir, "state", "state.json"),
				PrivKeyPath:  filepath.Join(dir, "keys", "priv.key"),
				PubJWKSPath:  filepath.Join(dir, "keys", "jwks.json"),
				ReplayPath:   filepath.Join(dir, "state", "replay.json"),
				AuditPath:    auditPath,
				WorkspaceDir: workspace,
			})
			if err != nil {
				t.Fatalf("BuildStack: %v", err)
			}
			defer stack.Close()

			if err := os.WriteFile(filepath.Join(workspace, "hop.txt"), []byte("hop ok"), 0600); err != nil {
				t.Fatalf("write workspace file: %v", err)
			}
			if tc.grantWorker {
				if _, err := stack.PAP.CreateGrant(context.Background(), pap.CreateGrantRequest{
					Subject:  "worker-01",
					Action:   domain.ActionFileRead,
					Resource: "hop.txt",
				}); err != nil {
					t.Fatalf("CreateGrant: %v", err)
				}
			}

			root, err := stack.TokenIssuer.IssueToken(token.IssueRequest{
				ClientID:     "client-orchestrator",
				ClientSecret: "orchestrator-secret-key-01",
				Subject:      "orchestrator-root",
				Scope:        "file:read file:write",
				Audience:     "authz-harness",
				TTL:          30 * time.Minute,
				Epoch:        1,
			}, token.IssueOptions{}, domain.AuditContext{TraceID: "t-setup", Actor: "setup", Reason: "token.issue"})
			if err != nil {
				t.Fatalf("issue root token: %v", err)
			}

			cfg := MultiHopConfig{
				WorkspaceDir: workspace,
				AuditPath:    auditPath,
				Audit:        stack.AuditWriter,
			}
			if tc.withGateway {
				cfg.Gateway = stack.PEP
			}
			spawner, err := NewMultiHopSpawner(cfg)
			if err != nil {
				t.Fatalf("NewMultiHopSpawner: %v", err)
			}

			exit, err := spawner.ExecuteMultiHop(context.Background(), MultiHopDelegationRequest{
				TraceID:       "trace-mh-inproc",
				RootToken:     root.TokenString,
				LeadSubject:   "lead-01",
				LeadScope:     "file:read file:write",
				WorkerSubject: "worker-01",
				WorkerScope:   "file:read",
				TargetFile:    "hop.txt",
				Action:        domain.ActionFileRead,
				Exchange:      stack.ExchangeService,
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if exit != tc.wantExit {
				t.Fatalf("exit = %v, want %v", exit, tc.wantExit)
			}
			if tc.wantAuditHas != "" {
				b, err := os.ReadFile(auditPath)
				if err != nil {
					t.Fatalf("read audit: %v", err)
				}
				if !strings.Contains(string(b), tc.wantAuditHas) {
					t.Errorf("audit log missing %q", tc.wantAuditHas)
				}
			}
		})
	}
}

// TestMultiHop_Detailed 는 ExecuteMultiHopDetailed 가 단계별 응답(Hop1, Hop2, Worker)과 종료 코드를
// MultiHopResult 구조체에 온전히 기록하는지 검증한다.
func TestMultiHop_Detailed(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "ws")
	auditPath := filepath.Join(dir, "audit", "audit.jsonl")

	stack, err := app.BuildStack(app.AppConfig{
		StatePath:    filepath.Join(dir, "state", "state.json"),
		PrivKeyPath:  filepath.Join(dir, "keys", "priv.key"),
		PubJWKSPath:  filepath.Join(dir, "keys", "jwks.json"),
		ReplayPath:   filepath.Join(dir, "state", "replay.json"),
		AuditPath:    auditPath,
		WorkspaceDir: workspace,
	})
	if err != nil {
		t.Fatalf("BuildStack: %v", err)
	}
	defer stack.Close()

	if err := os.WriteFile(filepath.Join(workspace, "detailed.txt"), []byte("detailed content"), 0600); err != nil {
		t.Fatalf("write workspace file: %v", err)
	}
	if _, err := stack.PAP.CreateGrant(context.Background(), pap.CreateGrantRequest{
		Subject:  "worker-01",
		Action:   domain.ActionFileRead,
		Resource: "detailed.txt",
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	root, err := stack.TokenIssuer.IssueToken(token.IssueRequest{
		ClientID:     "client-orchestrator",
		ClientSecret: "orchestrator-secret-key-01",
		Subject:      "orchestrator-root",
		Scope:        "file:read file:write",
		Audience:     "authz-harness",
		TTL:          30 * time.Minute,
		Epoch:        1,
	}, token.IssueOptions{}, domain.AuditContext{TraceID: "t-root", Actor: "setup", Reason: "token.issue"})
	if err != nil {
		t.Fatalf("issue root token: %v", err)
	}

	spawner, err := NewMultiHopSpawner(MultiHopConfig{
		WorkspaceDir: workspace,
		AuditPath:    auditPath,
		Audit:        stack.AuditWriter,
		Gateway:      stack.PEP,
	})
	if err != nil {
		t.Fatalf("NewMultiHopSpawner: %v", err)
	}

	t.Run("정상 2-Hop 상세 결과 수집", func(t *testing.T) {
		res, err := spawner.ExecuteMultiHopDetailed(context.Background(), MultiHopDelegationRequest{
			TraceID:       "trace-mh-detailed-ok",
			RootToken:     root.TokenString,
			LeadSubject:   "lead-01",
			LeadScope:     "file:read file:write",
			WorkerSubject: "worker-01",
			WorkerScope:   "file:read",
			TargetFile:    "detailed.txt",
			Action:        domain.ActionFileRead,
			Exchange:      stack.ExchangeService,
		})
		if err != nil {
			t.Fatalf("ExecuteMultiHopDetailed failed: %v", err)
		}
		if res.ExitCode != domain.ExitSuccess {
			t.Errorf("ExitCode = %v, want %v", res.ExitCode, domain.ExitSuccess)
		}
		if res.Hop1Result == nil {
			t.Fatal("res.Hop1Result should not be nil")
		}
		if res.Hop1Result.Claims.Subject != "lead-01" {
			t.Errorf("Hop1 Subject = %s, want lead-01", res.Hop1Result.Claims.Subject)
		}
		if res.Hop2Result == nil {
			t.Fatal("res.Hop2Result should not be nil")
		}
		if res.Hop2Result.Claims.Subject != "worker-01" {
			t.Errorf("Hop2 Subject = %s, want worker-01", res.Hop2Result.Claims.Subject)
		}
		if res.InprocResponse == nil {
			t.Fatal("res.InprocResponse should not be nil")
		}
		if res.InprocResponse.ExitCode != 0 {
			t.Errorf("InprocResponse.ExitCode = %d, want 0", res.InprocResponse.ExitCode)
		}
	})

	t.Run("2차 위임 스코프 초과 시 Hop1 보존 및 Hop2 거부", func(t *testing.T) {
		res, err := spawner.ExecuteMultiHopDetailed(context.Background(), MultiHopDelegationRequest{
			TraceID:       "trace-mh-detailed-deny",
			RootToken:     root.TokenString,
			LeadSubject:   "lead-01",
			LeadScope:     "file:read", // Lead는 read만 보유
			WorkerSubject: "worker-01",
			WorkerScope:   "file:read file:write", // Worker에게 write 위임 시도 (부모 초과)
			TargetFile:    "detailed.txt",
			Action:        domain.ActionFileRead,
			Exchange:      stack.ExchangeService,
		})
		if err == nil {
			t.Fatal("expected error for excessive scope delegation")
		}
		if res.ExitCode != domain.ExitAuthzDenied {
			t.Errorf("ExitCode = %v, want %v", res.ExitCode, domain.ExitAuthzDenied)
		}
		if res.Hop1Result == nil {
			t.Fatal("Hop1 should succeed before Hop2 denial")
		}
		if res.Hop2Result != nil {
			t.Errorf("Hop2Result should be nil on error, got %+v", res.Hop2Result)
		}
	})
}
