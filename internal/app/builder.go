// Package app 은 전체 하네스 시스템의 단일 합성 루트(Composition Root)를 제공하는 패키지다.
//
// [아키텍처 위치 및 중앙 배전반(Central Switchboard) 역할]
// 시스템 내의 모든 컴포넌트(인증 키 관리, 토큰 발급/검증, PDP 판단 두뇌, PEP 인가 관문, 감사 장부, 관측기 등)는
// 각자 독립적으로 객체를 생성하지 않고, 오직 본 패키지의 BuildStack 함수 하나를 통해 중앙에서 일괄 조립된다.
//
// [의존성 역전 원칙(DIP)의 결정체]
// 상위 수준 모듈이나 CLI 명령어들은 구체 구현체(예: *keys.Manager, *pep.gateway)를 직접 의존하지 않고,
// AppStack 에 바인딩된 인터페이스(keys.KeyManager, pep.Gateway, audit.Writer 등)만을 바라봄으로써
// 모듈 간 결합도를 최소화하고 단위 테스트 시 목(Mock) 객체 주입을 극대화한다.
//
// [Zone A 와 Zone B 의 물리적 권한 격리 (VerifyOnly)]
// - Zone A (민감 특권 구역): 개인 서명키(PrivKeyPath, 0700 권한), 토큰 발급기(TokenIssuer), 정책 관리점(PAP)
// - Zone B (격리 실행 구역): 공개 검증키(PubJWKSPath), 토큰 검증기(TokenVerifier), 인가 관문(PEP), 워커
// VerifyOnly 플래그가 활성화되면 Zone A 에 대한 파일 접근 및 컴포넌트 조립을 원천 차단하여
// 서브에이전트나 워커 프로세스가 개인키를 탈취하거나 부당하게 토큰을 자체 서명하는 보안 사고를 차단한다.
//
// [상호 참조 문서]
// - docs/작동원리/001-프로그램_정체성과_전체_생애주기.md
// - docs/작동원리/005-아키텍처_배선지도와_빠른_코드인수인계.md
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

// AppConfig 는 하네스 및 전체 런타임 스택 구동에 필요한 파일 시스템 경로와 런타임 옵션을 정의하는 구성체다.
// CLI 플래그나 테스트 픽스처로부터 생성되어 BuildStack 에 전달된다.
type AppConfig struct {
	// StatePath 는 정책 및 승인 상태(approval)를 저장하는 JSON 파일 경로다 (authz/state.Store).
	StatePath string

	// PrivKeyPath 는 Zone A 의 비대칭 서명 개인키 저장 경로다. VerifyOnly 모드에서는 무시된다.
	PrivKeyPath string

	// PubJWKSPath 는 공개키 세트(JWKS) 파일 경로다. 모든 토큰 검증 컴포넌트의 기준점이 된다.
	PubJWKSPath string

	// ReplayPath 는 토큰 jti 리플레이 방지 장부 파일 경로다 (authn/token.ReplayLedger).
	ReplayPath string

	// BudgetPath 는 토큰별 예산 소비 장부 파일 경로다.
	// 지정하지 않으면 filepath.Dir(ReplayPath)/budget_ledger.json 으로 자동 설정된다.
	BudgetPath string

	// AuditPath 는 무결성 SHA-256 해시 체인 기반 감사 로그 파일(audit.jsonl) 경로다.
	AuditPath string

	// WorkspaceDir 는 도구 실행 및 파일 I/O 가 격리되는 샌드박스 루트 디렉터리다 (jail.Jail).
	WorkspaceDir string

	// NetAllowList 는 net:fetch 도구가 접근 가능한 "host:port" 정규 형태의 화이트리스트다.
	// 비어 있으면 모든 네트워크 송신 시도가 즉시 차단(Fail-Closed)된다.
	NetAllowList []string

	// WithoutGateway 가 true 면 PEP 인가 게이트웨이 조립을 생략한다 (예: 토큰 발급 전용 CLI 등).
	WithoutGateway bool

	// VerifyOnly 가 true 면 Zone A(개인키) 접근을 차단하고, 서명키 자동 회전, Issuer, PAP 을 조립하지 않는다.
	// 서브에이전트 워커나 검증 전용 프로세스에서 최소 권한 원칙(PoLP)을 강제하는 스위치다.
	VerifyOnly bool

	// Clock 은 시간 추상화 인터페이스다.
	// 프로덕션에서는 domain.RealClock{}, 단위 테스트에서는 가상 시간(Mock Clock)을 주입한다.
	Clock domain.Clock

	// Observer 는 파이프라인 및 컴포넌트 생애주기 이벤트를 계측하는 관측 포트다.
	// nil 이면 slog.Default() 를 래핑한 기본 어댑터가 자동 할당된다.
	Observer observe.Observer
}

// AppStack 은 단일 합성 루트(BuildStack)를 통해 조립된 전체 런타임 객체 그래프(Object Graph)다.
// 상위 CLI 러너는 이 구조체 하나만 전달받아 원하는 서브시스템 인터페이스를 호출한다.
type AppStack struct {
	// Config 는 스택 생성 시 사용된 원본 설정이다.
	Config AppConfig

	// AuditWriter 는 시스템 전역 불변 감사 로그 기록기다 (internal/audit.Writer).
	AuditWriter audit.Writer

	// KeyStore 는 개인키/공개키 영속화 저장소다 (internal/authn/keys.Store).
	KeyStore keys.Store

	// KeyManager 는 키 생성, 순환(Rotate), 폐기(Revoke) 수명주기 제어 엔진이다 (internal/authn/keys.KeyManager).
	KeyManager keys.KeyManager

	// TokenIssuer 는 JWT 서명 및 토큰 발급기다 (internal/authn/token.TokenIssuer).
	// VerifyOnly 모드에서는 nil 로 격리된다.
	TokenIssuer token.TokenIssuer

	// TokenVerifier 는 JWT 서명 검증, 만료 시간 확인, 리플레이 캐시 검사를 수행한다 (internal/authn/token.TokenVerifier).
	TokenVerifier token.TokenVerifier

	// ClientReg 는 등록된 클라이언트 메타데이터 메모리 레지스트리다. VerifyOnly 모드에서는 nil 이다.
	ClientReg *token.InMemoryClientRegistry

	// ReplayLedger 는 jti 중복 소비 방지 장부다 (internal/authn/token.ReplayLedger).
	ReplayLedger token.ReplayLedger

	// BudgetLedger 는 토큰별 가용 자원 예산 차감/환불 장부다 (internal/authn/budget.Ledger).
	BudgetLedger budget.Ledger

	// ExchangeService 는 부모 토큰을 하위 권한 토큰으로 축소 위임(Downscoping)하는 교환기다 (internal/authn/exchange.Service).
	// VerifyOnly 모드에서는 nil 이다.
	ExchangeService exchange.Service

	// StateStore 는 정책 및 수동 승인 티켓 저장소다 (internal/authz/state.Store).
	StateStore state.Store

	// PAP 은 정책 관리 및 수동 승인 티켓을 발급하는 관리점이다 (internal/authz/pap.Service).
	// VerifyOnly 모드에서는 nil 이다.
	PAP pap.Service

	// PIP 는 PDP 인가 판단에 필요한 정책/스냅샷을 공급하는 정보점이다 (internal/authz/pip.Service).
	PIP pip.Service

	// PDP 는 파일 I/O 없는 순수 함수로 권한을 계산하는 인가 결정점이다 (internal/authz/pdp.Service).
	PDP pdp.Service

	// Jail 은 디렉터리 탈출(../) 및 심볼릭 링크 공격을 차단하는 파일시스템 격리소다 (internal/jail.Jail).
	Jail jail.Jail

	// PEP 는 10단계 파이프라인을 구동하여 도구 실행을 최종 통제하는 인가 집행점이다 (internal/authz/pep.Gateway).
	PEP pep.Gateway
}

// Close 는 AppStack 이 점유한 OS 자원(감사 로그 파일 디스크립터 등)을 안전하게 플러시하고 반납한다.
// Fail-Closed 및 Zero Leakage 원칙에 따라 프로세스 종료 시 반드시 호출(defer s.Close())되어야 한다.
func (s *AppStack) Close() error {
	if s != nil && s.AuditWriter != nil {
		return s.AuditWriter.Close()
	}
	return nil
}

// BuildStack 은 AppConfig 를 바탕으로 디렉터리 권한을 준비하고 모든 서브시스템 의존성을 올바른 순서로 조립한다.
//
// [조립 생애주기 6단계 (Assembly Lifecycle)]
// 1. 디렉터리 준비: 감사, 리플레이, 예산, 상태 파일 저장 디렉터리 생성 (0755).
//    - 주의: Zone A(개인키 폴더)는 여기서 생성하지 않고 keys.NewFileStore 내부에서 엄격한 0700 권한으로 생성.
// 2. AuditWriter 초기화: 모든 후속 모듈의 감사 기록을 위해 audit.jsonl 작성을 최우선 시작.
// 3. Keys 모듈 초기화: 파일 저장소 및 KeyManager 생성. 필요 시 초기 서명키 자동 회전(RotateKey) 수행.
// 4. State/PIP/PAP/PDP 초기화: 상태 저장소 구축 후 순수 판단 두뇌(PDP) 배선.
// 5. Token/Budget/Exchange 초기화: 토큰 발급/검증 엔진, 리플레이 장부, 예산 장부, 축소 위임 서비스 조립.
// 6. Jail/Guard/PEP 게이트웨이 초기화: 샌드박스, 네트워크/프로세스 가드, 10단계 검문소 게이트웨이 완성.
//
// [Fail-Closed 에러 처리]:
// 조립 과정 중 어느 한 단계라도 실패하면, 이전에 열어둔 AuditWriter 를 즉시 닫고 fmt.Errorf("...: %w", err) 로 래핑하여 반환한다.
func BuildStack(cfg AppConfig) (*AppStack, error) {
	// 시간 추상화 기본값 보장 (테스트용 Clock 이 주입되지 않은 경우 OS 실제 시간 바인딩)
	if cfg.Clock == nil {
		cfg.Clock = domain.RealClock{}
	}

	// 예산 장부 기본 경로 자동 유도 (ReplayPath 와 동일 디렉터리)
	if cfg.BudgetPath == "" && cfg.ReplayPath != "" {
		cfg.BudgetPath = filepath.Join(filepath.Dir(cfg.ReplayPath), "budget_ledger.json")
	}

	// 1. 디렉터리 준비:
	// 상태, 공개키, 리플레이, 예산, 감사 장부 디렉터리를 0755 권한으로 준비한다.
	// 단, 개인키(Zone A)는 keys.NewFileStore 가 0700 으로 별도 격리 생성하므로 여기서 제외된다.
	pathsToEnsure := []string{
		cfg.StatePath,
		cfg.PubJWKSPath,
		cfg.ReplayPath,
		cfg.BudgetPath,
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

	// 2. AuditWriter 초기화:
	// 감사 추적(Audit Trail)은 모든 인가 및 보안 이벤트의 단일 진실 공급원이므로 시스템에서 가장 먼저 준비된다.
	auditWriter, err := audit.NewJSONLWriter(cfg.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("app builder: audit writer: %w", err)
	}

	// 3. 키 스토어 및 키 매니저 초기화:
	// VerifyOnly 활성화 시 PrivKeyPath 를 빈 문자열로 강제하여 Zone A 개인키 파일 디스크립터 생성을 원천 차단한다.
	privPath := cfg.PrivKeyPath
	if cfg.VerifyOnly {
		privPath = "" // Zone A 접근 차단 (최소 권한 원칙)
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

	// 서명 키 초기 확인 및 자동 회전:
	// 토큰 발급 스택(Zone A)에서 유효한 활성 서명키가 없으면 초기 Ed25519 서명키를 자동으로 생성/회전한다.
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

	// 4. 인가 상태 저장소 및 PAP / PIP / PDP 조립:
	// ExchangeService 의 PIP 스냅샷 공급자 배선을 위해 토큰 교환기보다 먼저 조립된다.
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

		// PAP 은 관리 권한이 필요한 Zone A 환경에서만 조립
		if !cfg.VerifyOnly {
			papSvc = pap.NewService(stateStore, auditWriter, pap.WithClock(cfg.Clock))
		}
		// PIP 는 상태 저장소로부터 읽기 전용 스냅샷을 제공
		pipSvc = pip.NewService(stateStore, pip.WithClock(cfg.Clock))
		// PDP 는 파일 I/O 없이 메모리 상의 스냅샷과 클레임만을 대조하는 순수 계산 두뇌
		pdpSvc = pdp.NewService(pipSvc, auditWriter, pdp.WithClock(cfg.Clock))
	}

	// 5. 토큰 발급기, 검증기 및 교환기 조립:
	var budgetLedger budget.Ledger
	var clientReg *token.InMemoryClientRegistry
	var tokenIssuer token.TokenIssuer
	var replayLedger token.ReplayLedger
	var tokenVerifier token.TokenVerifier
	var exchangeSvc exchange.Service
	if cfg.PubJWKSPath != "" && cfg.ReplayPath != "" {
		// 예산 장부 (차감 및 보상 환불)
		bl, err := budget.NewFileLedger(cfg.BudgetPath, cfg.Clock)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: budget ledger: %w", err)
		}
		budgetLedger = bl

		// Zone A 에서만 토큰 발급기(Issuer) 조립
		if !cfg.VerifyOnly {
			clientReg = token.NewInMemoryClientRegistry()
			tokenIssuer = token.NewService(keyMgr, clientReg, auditWriter, cfg.Clock, token.WithBudgetLedger(budgetLedger))
		}

		// 리플레이 방지 장부 (jti 중복 사용 원천 차단)
		rl, err := token.NewFileReplayLedger(cfg.ReplayPath, cfg.Clock)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: replay ledger: %w", err)
		}
		replayLedger = rl

		// 토큰 검증기 (공개키 기반 서명 검증 + 리플레이 검증)
		tokenVerifier = token.NewVerifier(keyMgr, replayLedger, auditWriter, cfg.Clock)

		// 축소 위임(Downscoping) 서비스 조립 (Zone A 전용)
		if !cfg.VerifyOnly {
			exOpts := []exchange.Option{exchange.WithBudgetLedger(budgetLedger)}
			if pipSvc != nil {
				exOpts = append(exOpts, exchange.WithSnapshotProvider(pipSvc))
			}
			es, err := exchange.NewExchangeService(tokenIssuer, tokenVerifier, clientReg, nil, auditWriter, cfg.Clock, exOpts...)
			if err != nil {
				_ = auditWriter.Close()
				return nil, fmt.Errorf("app builder: exchange service: %w", err)
			}
			exchangeSvc = es
		}
	}

	// 6. 워크스페이스 격리(Jail), 관측기 및 PEP 게이트웨이 조립:
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

	// [Go 관용구: 인터페이스 nil 보존 (Interface Nil Preservation)]
	// Go 언어에서 typed nil(구체 타입 포인터가 nil인 경우)을 인터페이스 변수에 대입하면,
	// 인터페이스 내부 표현 (타입 정보 + 값 포인터) 중 타입 정보가 채워져 '인터페이스 != nil' 판정이 참이 되는 중대한 함정이 발생한다.
	// 이를 방지하기 위해 stateStore 가 nil 일 때는 인터페이스 변수 approvalConsumer 자체를 원시 nil 상태로 보존한다.
	var approvalConsumer pep.ApprovalConsumer
	if stateStore != nil {
		approvalConsumer = state.NewApprovalConsumer(stateStore)
	}

	if !cfg.WithoutGateway && pdpSvc != nil && tokenVerifier != nil {
		// 네트워크 및 OS 프로세스 가드레일 초기화
		netGuard, err := netguard.NewGuard(cfg.NetAllowList, 0, 0)
		if err != nil {
			_ = auditWriter.Close()
			return nil, fmt.Errorf("app builder: net guard: %w", err)
		}
		var execRunner *execguard.Runner
		if cfg.WorkspaceDir != "" {
			execRunner = execguard.NewRunner(cfg.WorkspaceDir, 0, 0)
		}

		// 10단계 컨베이어 벨트를 갖춘 최종 인가 관문 생성
		gw, err := pep.NewGateway(pep.Config{
			NetGuard:         netGuard,
			ExecRunner:       execRunner,
			Verifier:         tokenVerifier,
			PDP:              pdpSvc,
			Jail:             workspaceJail,
			AuditWriter:      auditWriter,
			Clock:            cfg.Clock,
			Observer:         obs,
			BudgetLedger:     budgetLedger,
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
