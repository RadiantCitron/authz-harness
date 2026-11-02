package app

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"authz-harness/internal/audit"
	"authz-harness/internal/authn/keys"
	"authz-harness/internal/authn/token"
	"authz-harness/internal/authz/pap"
	"authz-harness/internal/authz/pdp"
	"authz-harness/internal/authz/pep"
	"authz-harness/internal/authz/pip"
	"authz-harness/internal/authz/state"
	"authz-harness/internal/domain"
	"authz-harness/internal/jail"
)

// AppConfig 는 하네스 및 전체 런타임 스택 구동에 필요한 파일 경로 및 주입 요소를 포함한다.
type AppConfig struct {
	StatePath    string
	PrivKeyPath  string
	PubJWKSPath  string
	ReplayPath   string
	AuditPath    string
	WorkspaceDir string
	Clock        domain.Clock
	Logger       *slog.Logger
}

// AppStack 은 단일 합성 루트(Composition Root)를 통해 생성된 일원화된 컴포넌트 집합이다.
type AppStack struct {
	Config        AppConfig
	AuditWriter   audit.Writer
	KeyStore      keys.Store
	KeyManager    keys.KeyManager
	TokenIssuer   token.TokenIssuer
	TokenVerifier token.TokenVerifier
	ClientReg     *token.InMemoryClientRegistry
	ReplayLedger  token.ReplayLedger
	StateStore    state.Store
	PAP           pap.Service
	PIP           pip.Service
	PDP           pdp.Service
	Jail          jail.Jail
	PEP           pep.Gateway
}

// Close 는 AppStack 내부의 리소스(AuditWriter 파일 디스크립터 등)를 안전하게 정리한다.
func (s *AppStack) Close() error {
	if s.AuditWriter != nil {
		return s.AuditWriter.Close()
	}
	return nil
}

// BuildStack 은 AppConfig 를 받아 필요한 디렉터리를 준비하고 전체 의존성을 조립한 AppStack 을 반환한다.
func BuildStack(cfg AppConfig) (*AppStack, error) {
	if cfg.Clock == nil {
		cfg.Clock = domain.RealClock{}
	}

	// 1. 디렉터리 준비
	pathsToEnsure := []string{
		cfg.StatePath,
		cfg.PrivKeyPath,
		cfg.PubJWKSPath,
		cfg.ReplayPath,
		cfg.AuditPath,
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
	keyStore, err := keys.NewFileStore(cfg.PrivKeyPath, cfg.PubJWKSPath)
	if err != nil {
		_ = auditWriter.Close()
		return nil, fmt.Errorf("app builder: key store: %w", err)
	}

	keyMgr, err := keys.NewManager(keyStore, auditWriter, keys.WithClock(cfg.Clock))
	if err != nil {
		_ = auditWriter.Close()
		return nil, fmt.Errorf("app builder: key manager: %w", err)
	}

	// 서명 키 초기 확인 및 자동 회전
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

	// 4. 토큰 발급기 및 검증기
	clientReg := token.NewInMemoryClientRegistry()
	tokenIssuer := token.NewService(keyMgr, clientReg, auditWriter, cfg.Clock)

	replayLedger, err := token.NewFileReplayLedger(cfg.ReplayPath, cfg.Clock)
	if err != nil {
		_ = auditWriter.Close()
		return nil, fmt.Errorf("app builder: replay ledger: %w", err)
	}

	tokenVerifier := token.NewVerifier(keyMgr, replayLedger, auditWriter, cfg.Clock)

	// 5. 인가 상태 저장소 및 PAP / PIP / PDP
	stateStore, err := state.NewFileStore(cfg.StatePath)
	if err != nil {
		_ = auditWriter.Close()
		return nil, fmt.Errorf("app builder: state store: %w", err)
	}

	papSvc := pap.NewService(stateStore, auditWriter, pap.WithClock(cfg.Clock))
	pipSvc := pip.NewService(stateStore)
	pdpSvc := pdp.NewService(pipSvc, auditWriter)

	// 6. 워크스페이스 격리(Jail) 및 PEP 게이트웨이
	workspaceJail, err := jail.New(cfg.WorkspaceDir)
	if err != nil {
		_ = auditWriter.Close()
		return nil, fmt.Errorf("app builder: jail: %w", err)
	}

	pepGateway, err := pep.NewGateway(pep.Config{
		Verifier:    tokenVerifier,
		PDP:         pdpSvc,
		Jail:        workspaceJail,
		AuditWriter: auditWriter,
		Clock:       cfg.Clock,
		Logger:      cfg.Logger,
	})
	if err != nil {
		_ = auditWriter.Close()
		return nil, fmt.Errorf("app builder: pep gateway: %w", err)
	}

	return &AppStack{
		Config:        cfg,
		AuditWriter:   auditWriter,
		KeyStore:      keyStore,
		KeyManager:    keyMgr,
		TokenIssuer:   tokenIssuer,
		TokenVerifier: tokenVerifier,
		ClientReg:     clientReg,
		ReplayLedger:  replayLedger,
		StateStore:    stateStore,
		PAP:           papSvc,
		PIP:           pipSvc,
		PDP:           pdpSvc,
		Jail:          workspaceJail,
		PEP:           pepGateway,
	}, nil
}
