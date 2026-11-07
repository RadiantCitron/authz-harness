package app

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/budget"
	"authz-harness/internal/authn/exchange"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
	"authz-harness/internal/execguard"
	"authz-harness/internal/jail"
	"authz-harness/internal/netguard"
	"authz-harness/internal/observe"
	"authz-harness/internal/observe/slogadapter"
)

// AppConfig 는 하네스 및 전체 런타임 스택 구동에 필요한 파일 경로 및 주입 요소를 포함한다.
type AppConfig struct {
	StatePath    string
	PrivKeyPath  string
	PubJWKSPath  string
	ReplayPath   string
	BudgetPath   string // 비면 filepath.Dir(ReplayPath)/budget_ledger.json
	AuditPath    string
	WorkspaceDir string
	NetAllowList []string // net:fetch 허용 host:port (정규 형태). 비면 net:fetch 는 전부 거부
	VerifyOnly   bool     // true: Zone A(개인키) 미접근, 서명키 자동 회전/Issuer/PAP 미조립 (서브에이전트/PEP 검증 전용)
	Clock        domain.Clock
	Observer     observe.Observer
}

// AppStack 은 단일 합성 루트(Composition Root)를 통해 생성된 일원화된 컴포넌트 집합이다.
type AppStack struct {
	Config          AppConfig
	AuditWriter     audit.Writer
	KeyStore        keys.Store
	KeyManager      keys.KeyManager
	TokenIssuer     token.TokenIssuer // VerifyOnly 모드에서는 nil
	TokenVerifier   token.TokenVerifier
	ClientReg       *token.InMemoryClientRegistry // VerifyOnly 모드에서는 nil
	ReplayLedger    token.ReplayLedger
	BudgetLedger    budget.Ledger
	ExchangeService exchange.Service // VerifyOnly 모드에서는 nil
	StateStore      state.Store
	PAP             pap.Service // VerifyOnly 모드에서는 nil
	PIP             pip.Service
	PDP             pdp.Service
	Jail            jail.Jail
	PEP             pep.Gateway
}

// Close 는 AppStack 내부의 리소스(AuditWriter 파일 디스크립터 등)를 안전하게 정리한다.
func (s *AppStack) Close() error {
	if s != nil && s.AuditWriter != nil {
		return s.AuditWriter.Close()
	}
	return nil
}

// BuildStack 은 AppConfig 를 받아 필요한 디렉터리를 준비하고 전체 의존성을 조립한 AppStack 을 반환한다.
func BuildStack(cfg AppConfig) (*AppStack, error) {
	if cfg.Clock == nil {
		cfg.Clock = domain.RealClock{}
	}

	if cfg.BudgetPath == "" && cfg.ReplayPath != "" {
		cfg.BudgetPath = filepath.Join(filepath.Dir(cfg.ReplayPath), "budget_ledger.json")
	}

	// 1. 디렉터리 준비
	pathsToEnsure := []string{
		cfg.StatePath,
		cfg.PubJWKSPath,
		cfg.ReplayPath,
		cfg.BudgetPath,
		cfg.AuditPath,
	}
	if !cfg.VerifyOnly && cfg.PrivKeyPath != "" {
		pathsToEnsure = append(pathsToEnsure, cfg.PrivKeyPath)
	}

	for _, p := range pathsToEnsure {
		if p != "" {
			dir := filepath.Dir(p)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("app builder: failed to create dir %s: %w", dir, err)
			}
		}
	}
	if cfg.WorkspaceDir != "" {
		if err := os.MkdirAll(cfg.WorkspaceDir, 0755); err != nil {
			return nil, fmt.Errorf("app builder: failed to create workspace dir %s: %w", cfg.WorkspaceDir, err)
		}
	}

	// 2. AuditWriter 초기화
	auditWriter, err := audit.NewJSONLWriter(cfg.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("app builder: audit writer: %w", err)
	}

	// 3. 키 스토어 및 키 매니저 초기화
	privPath := cfg.PrivKeyPath
	if cfg.VerifyOnly {
		privPath = "" // Zone A 접근 차단
	}

	var keyStore keys.Store
	var keyMgr keys.KeyManager
	if cfg.PubJWKSPath != "" {
		ks, err := keys.NewFileStore(privPath, cfg.PubJWKSPath)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: key store: %w", err)
		}
		keyStore = ks

		km, err := keys.NewManager(keyStore, auditWriter, keys.WithClock(cfg.Clock))
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: key manager: %w", err)
		}
		keyMgr = km
	}

	// 서명 키 초기 확인 및 자동 회전 (토큰 발급 스택에서만: keys CLI 등 부분 경로는 제외)
	if !cfg.VerifyOnly && keyMgr != nil && cfg.ReplayPath != "" {
		activeKey, err := keyMgr.GetActiveSigningKey()
		if err != nil || activeKey == nil {
			if _, err := keyMgr.RotateKey(domain.AuditContext{
				TraceID: "builder-init-rotation",
				Actor:   "system",
				Reason:  "initial active key setup via app builder",
			}); err != nil {
				_ = auditWriter.Close()
				return nil, fmt.Errorf("app builder: initial key rotation: %w", err)
			}
		}
	}

	// 4. 인가 상태 저장소 및 PAP / PIP / PDP (ExchangeService 에 PIP 스냅샷 공급자를 배선하기 위해 먼저 조립)
	var stateStore state.Store
	var papSvc pap.Service
	var pipSvc pip.Service
	var pdpSvc pdp.Service

	if cfg.StatePath != "" {
		st, err := state.NewFileStore(cfg.StatePath, state.WithClock(cfg.Clock))
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: state store: %w", err)
		}
		stateStore = st

		if !cfg.VerifyOnly {
			papSvc = pap.NewService(stateStore, auditWriter, pap.WithClock(cfg.Clock))
		}
		pipSvc = pip.NewService(stateStore, pip.WithClock(cfg.Clock))
		pdpSvc = pdp.NewService(pipSvc, auditWriter, pdp.WithClock(cfg.Clock))
	}

	// 5. 토큰 발급기, 검증기 및 교환기 (키 + 리플레이 경로가 있을 때만)
	var budgetLedger budget.Ledger
	var clientReg *token.InMemoryClientRegistry
	var tokenIssuer token.TokenIssuer
	var replayLedger token.ReplayLedger
	var tokenVerifier token.TokenVerifier
	var exchangeSvc exchange.Service
	if cfg.PubJWKSPath != "" && cfg.ReplayPath != "" {
		bl, err := budget.NewFileLedger(cfg.BudgetPath, cfg.Clock)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: budget ledger: %w", err)
		}
		budgetLedger = bl

		if !cfg.VerifyOnly {
			clientReg = token.NewInMemoryClientRegistry()
			tokenIssuer = token.NewService(keyMgr, clientReg, auditWriter, cfg.Clock, token.WithBudgetLedger(budgetLedger))
		}

		rl, err := token.NewFileReplayLedger(cfg.ReplayPath, cfg.Clock)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: replay ledger: %w", err)
		}
		replayLedger = rl

		tokenVerifier = token.NewVerifier(keyMgr, replayLedger, auditWriter, cfg.Clock)

		if !cfg.VerifyOnly {
			exOpts := []exchange.Option{exchange.WithBudgetLedger(budgetLedger)}
			if pipSvc != nil {
				exOpts = append(exOpts, exchange.WithSnapshotProvider(pipSvc))
			}
			exchangeSvc = exchange.NewExchangeService(tokenIssuer, tokenVerifier, clientReg, nil, auditWriter, cfg.Clock, exOpts...)
		}
	}

	// 6. 워크스페이스 격리(Jail) 및 PEP 게이트웨이
	var workspaceJail jail.Jail
	if cfg.WorkspaceDir != "" {
		j, err := jail.New(cfg.WorkspaceDir)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: jail: %w", err)
		}
		workspaceJail = j
	}

	obs := cfg.Observer
	if obs == nil {
		obs = slogadapter.New(slog.Default())
	}

	var pepGateway pep.Gateway
	var approvalConsumer pep.ApprovalConsumer // 인터페이스 nil 보존 (stateStore 없으면 미배선)
	if stateStore != nil {
		approvalConsumer = state.NewApprovalConsumer(stateStore)
	}
	if pdpSvc != nil && tokenVerifier != nil && workspaceJail != nil {
		netGuard, err := netguard.NewGuard(cfg.NetAllowList, 0, 0)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: net guard: %w", err)
		}
		var execRunner *execguard.Runner
		if cfg.WorkspaceDir != "" {
			execRunner = execguard.NewRunner(cfg.WorkspaceDir, 0, 0)
		}
		gw, err := pep.NewGateway(pep.Config{
			NetGuard:     netGuard,
			ExecRunner:   execRunner,
			Verifier:     tokenVerifier,
			PDP:          pdpSvc,
			Jail:         workspaceJail,
			AuditWriter:  auditWriter,
			Clock:        cfg.Clock,
			Observer:     obs,
			BudgetLedger: budgetLedger,

			ApprovalConsumer: approvalConsumer,
		})
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: pep gateway: %w", err)
		}
		pepGateway = gw
	}

	return &AppStack{
		Config:          cfg,
		AuditWriter:     auditWriter,
		KeyStore:        keyStore,
		KeyManager:      keyMgr,
		TokenIssuer:     tokenIssuer,
		TokenVerifier:   tokenVerifier,
		ClientReg:       clientReg,
		ReplayLedger:    replayLedger,
		BudgetLedger:    budgetLedger,
		ExchangeService: exchangeSvc,
		StateStore:      stateStore,
		PAP:             papSvc,
		PIP:             pipSvc,
		PDP:             pdpSvc,
		Jail:            workspaceJail,
		PEP:             pepGateway,
	}, nil
}
