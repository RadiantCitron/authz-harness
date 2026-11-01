package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"authz-harness/internal/audit"
	"authz-harness/internal/domain"
)

// SandboxConfig 는 격리 샌드박스 생성 설정이다.
type SandboxConfig struct {
	BaseDir   string        // 임시 루트 디렉터리 (공백 시 os.MkdirTemp 사용)
	ClockTime time.Time     // 가상 시계 기준 시각
}

// SandboxEnvironment 는 단일 시나리오가 실행되는 독립된 3-Zone 파일 및 감사 공간이다.
type SandboxEnvironment struct {
	RootDir      string        // 샌드박스 루트 경로
	PrivKeyPath  string        // Zone A: 서명 개인키 파일 경로
	PubJWKSPath  string        // Zone B: 공개 검증 키(JWKS) 파일 경로
	StatePath    string        // Zone B: Grant/Epoch 상태 파일 경로
	ReplayPath   string        // Zone B: Replay 방지 원장 파일 경로
	WorkspaceDir string        // Zone C: Workspace 격리 디렉터리 경로
	AuditPath    string        // 감사 로그 (audit.jsonl) 경로
	MockClock    domain.Clock  // 결정론적 가상 시계
}

// fixedClock 은 고정된 시각을 반환하는 가상 시계다.
type fixedClock struct {
	t time.Time
}

func (c *fixedClock) Now() time.Time {
	return c.t
}

// NewSandboxEnvironment 는 독립된 임시 디렉터리에 Zone A/B/C 구조를 생성하고 초기화한다.
func NewSandboxEnvironment(cfg SandboxConfig) (*SandboxEnvironment, error) {
	var rootDir string
	var err error

	if cfg.BaseDir != "" {
		if err := os.MkdirAll(cfg.BaseDir, 0700); err != nil {
			return nil, fmt.Errorf("harness sandbox: failed to create base dir: %w", err)
		}
		rootDir, err = os.MkdirTemp(cfg.BaseDir, "scenario-sandbox-*")
	} else {
		rootDir, err = os.MkdirTemp("", "authz-harness-sandbox-*")
	}
	if err != nil {
		return nil, fmt.Errorf("harness sandbox: failed to create temp root dir: %w", err)
	}

	// 1. Zone A: 서명 개인키 전용 디렉터리 (0700)
	zoneADir := filepath.Join(rootDir, "zone_a")
	if err := os.MkdirAll(zoneADir, 0700); err != nil {
		_ = os.RemoveAll(rootDir)
		return nil, fmt.Errorf("harness sandbox: failed to create zone A dir: %w", err)
	}
	privKeyPath := filepath.Join(zoneADir, "private_keys.json")

	// 2. Zone B: 공개 JWKS, Grant/Epoch 상태, Replay 원장 디렉터리 (0700)
	zoneBDir := filepath.Join(rootDir, "zone_b")
	if err := os.MkdirAll(zoneBDir, 0700); err != nil {
		_ = os.RemoveAll(rootDir)
		return nil, fmt.Errorf("harness sandbox: failed to create zone B dir: %w", err)
	}
	pubJWKSPath := filepath.Join(zoneBDir, "jwks.json")
	statePath := filepath.Join(zoneBDir, "grants_state.json")
	replayPath := filepath.Join(zoneBDir, "replay_ledger.json")

	// 3. Zone C: Workspace Jail 대상 디렉터리 (0700)
	workspaceDir := filepath.Join(rootDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0700); err != nil {
		_ = os.RemoveAll(rootDir)
		return nil, fmt.Errorf("harness sandbox: failed to create workspace dir: %w", err)
	}

	// 4. 감사 로그 파일 (audit.jsonl) 경로 (초기 빈 파일 생성, 0600)
	auditPath := filepath.Join(rootDir, "audit.jsonl")
	auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		_ = os.RemoveAll(rootDir)
		return nil, fmt.Errorf("harness sandbox: failed to init audit file: %w", err)
	}
	_ = auditFile.Close()

	var clk domain.Clock
	if !cfg.ClockTime.IsZero() {
		clk = &fixedClock{t: cfg.ClockTime.UTC()}
	} else {
		clk = domain.RealClock{}
	}

	return &SandboxEnvironment{
		RootDir:      rootDir,
		PrivKeyPath:  privKeyPath,
		PubJWKSPath:  pubJWKSPath,
		StatePath:    statePath,
		ReplayPath:   replayPath,
		WorkspaceDir: workspaceDir,
		AuditPath:    auditPath,
		MockClock:    clk,
	}, nil
}

// Cleanup 은 생성된 샌드박스 디렉터리와 모든 임시 리소스를 안전하게 제거한다.
func (env *SandboxEnvironment) Cleanup() error {
	if env == nil || env.RootDir == "" {
		return nil
	}
	return os.RemoveAll(env.RootDir)
}

// ReadWorkspaceFile 은 Zone C Workspace 디렉터리 내의 파일을 안전하게 읽는다.
func (env *SandboxEnvironment) ReadWorkspaceFile(relPath string) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("sandbox is nil")
	}
	targetPath := filepath.Join(env.WorkspaceDir, relPath)
	return os.ReadFile(targetPath)
}

// WorkspaceFileExists 는 Zone C Workspace 내 파일 존재 여부를 확인한다.
func (env *SandboxEnvironment) WorkspaceFileExists(relPath string) bool {
	if env == nil {
		return false
	}
	targetPath := filepath.Join(env.WorkspaceDir, relPath)
	_, err := os.Stat(targetPath)
	return err == nil
}

// GetWorkspaceFileSize 는 Zone C Workspace 내 파일 크기(바이트)를 반환한다 (없으면 0).
func (env *SandboxEnvironment) GetWorkspaceFileSize(relPath string) int64 {
	if env == nil {
		return 0
	}
	targetPath := filepath.Join(env.WorkspaceDir, relPath)
	info, err := os.Stat(targetPath)
	if err != nil {
		return 0
	}
	return info.Size()
}

// ReadAuditEvents 는 샌드박스 내 audit.jsonl의 모든 감사 이벤트를 파싱하여 반환한다.
func (env *SandboxEnvironment) ReadAuditEvents() ([]audit.Event, error) {
	if env == nil {
		return nil, fmt.Errorf("sandbox is nil")
	}
	f, err := os.Open(env.AuditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("harness sandbox: failed to open audit file: %w", err)
	}
	defer f.Close()

	var events []audit.Event
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("harness sandbox: line %d unmarshal error: %w", lineNum, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("harness sandbox: scan audit events error: %w", err)
	}
	return events, nil
}
