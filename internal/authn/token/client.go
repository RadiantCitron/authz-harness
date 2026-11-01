package token

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"authz-harness/internal/domain"
)

var (
	// ErrUnknownClient 는 미등록 클라이언트 ID 오류다.
	ErrUnknownClient = errors.New("unknown client id")

	// ErrInvalidSecret 은 클라이언트 시크릿 불일치 오류다.
	ErrInvalidSecret = errors.New("invalid client secret")

	// ErrClientSuspended 는 비활성화/정지된 클라이언트 오류다.
	ErrClientSuspended = errors.New("client suspended")
)

// ClientInfo 는 등록된 클라이언트의 신원 정보다.
type ClientInfo struct {
	ClientID    string   `json:"client_id"`
	Description string   `json:"description"`
	AllowedSubs []string `json:"allowed_subs"`
	Active      bool     `json:"active"`
}

// ClientRegistry 는 클라이언트 인증 인터페이스다.
type ClientRegistry interface {
	AuthenticateClient(clientID, clientSecret string) (*ClientInfo, error)
	GetClient(clientID string) (*ClientInfo, error)
}

type clientEntry struct {
	info   ClientInfo
	secret string
}

// InMemoryClientRegistry 는 메모리 기반 클라이언트 레지스트리 구현체다.
type InMemoryClientRegistry struct {
	clients map[string]clientEntry
}

// NewInMemoryClientRegistry 는 사전 등록된 기본 클라이언트들을 포함하는 레지스트리를 생성한다.
func NewInMemoryClientRegistry() *InMemoryClientRegistry {
	r := &InMemoryClientRegistry{
		clients: make(map[string]clientEntry),
	}

	// 기본 사전 등록 클라이언트
	// 1. client-orchestrator: 오케스트레이터(팀장) 워크로드
	r.clients["client-orchestrator"] = clientEntry{
		info: ClientInfo{
			ClientID:    "client-orchestrator",
			Description: "Orchestration & Task Delegation Coordinator",
			AllowedSubs: []string{"*"},
			Active:      true,
		},
		secret: "orchestrator-secret-key-01",
	}

	// 2. client-subagent: 서브에이전트(작업자) 워크로드
	r.clients["client-subagent"] = clientEntry{
		info: ClientInfo{
			ClientID:    "client-subagent",
			Description: "Task Worker Subagent",
			AllowedSubs: []string{"worker-01", "worker-02", "worker-03"},
			Active:      true,
		},
		secret: "subagent-secret-key-02",
	}

	// 3. client-admin: 관리자 워크로드
	r.clients["client-admin"] = clientEntry{
		info: ClientInfo{
			ClientID:    "client-admin",
			Description: "Security & Harness Administrator",
			AllowedSubs: []string{"*"},
			Active:      true,
		},
		secret: "admin-secret-key-00",
	}

	return r
}

// RegisterClient 는 신규 클라이언트를 등록한다 (테스트 및 확장용).
func (r *InMemoryClientRegistry) RegisterClient(clientID, secret, description string, allowedSubs []string, active bool) {
	r.clients[clientID] = clientEntry{
		info: ClientInfo{
			ClientID:    clientID,
			Description: description,
			AllowedSubs: allowedSubs,
			Active:      active,
		},
		secret: secret,
	}
}

// AuthenticateClient 는 client_id 와 client_secret 을 정시성(subtle.ConstantTimeCompare)으로 검증한다.
func (r *InMemoryClientRegistry) AuthenticateClient(clientID, clientSecret string) (*ClientInfo, error) {
	entry, exists := r.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("%w: %s (%s)", ErrUnknownClient, clientID, domain.ReasonAuthnUnknownClient)
	}

	if !entry.info.Active {
		return nil, fmt.Errorf("%w: %s (%s)", ErrClientSuspended, clientID, domain.ReasonAuthnClientSuspended)
	}

	secA := []byte(clientSecret)
	secB := []byte(entry.secret)
	if subtle.ConstantTimeCompare(secA, secB) != 1 {
		return nil, fmt.Errorf("%w: %s (%s)", ErrInvalidSecret, clientID, domain.ReasonAuthnInvalidSecret)
	}

	info := entry.info
	return &info, nil
}

// GetClient 는 클라이언트 정보를 반환한다.
func (r *InMemoryClientRegistry) GetClient(clientID string) (*ClientInfo, error) {
	entry, exists := r.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUnknownClient, clientID)
	}
	info := entry.info
	return &info, nil
}

// IsSubjectAllowed 는 클라이언트가 해당 subject 명의로 토큰을 요청할 수 있는지 검사한다.
func (c *ClientInfo) IsSubjectAllowed(sub string) bool {
	for _, pattern := range c.AllowedSubs {
		if pattern == "*" || pattern == sub {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(sub, prefix) {
				return true
			}
		}
	}
	return false
}
