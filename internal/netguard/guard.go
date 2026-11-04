// Package netguard 는 net:fetch 도구를 위한 루프백 전용 URL 정규화와 egress 가드다.
//
// 검사한 주소와 실제로 연결하는 주소가 같아야 한다. 그래서 DNS 조회, 리다이렉트 추종,
// 환경변수 프록시를 모두 막고 연결 함수가 검증된 주소만 연결하게 고정한다.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"authz-harness/internal/domain"
)

const (
	stageName       = "netguard"
	defaultMaxBytes = int64(1 << 20)
	defaultTimeout  = 5 * time.Second
)

// Target 은 정규화된 요청 대상이다.
type Target struct {
	HostPort string // "127.0.0.1:<port>" 또는 "[::1]:<port>"
	URL      string // "http://" + HostPort + path[?query]
}

func deny(msg string) error {
	return domain.NewError(domain.ReasonEgressDenied, stageName, msg, nil)
}

// ParseTarget 은 raw 를 정규 Target 으로 바꾸는 순수 함수다(소켓·DNS·allow-list 없음).
func ParseTarget(raw string) (Target, error) {
	if raw == "" {
		return Target{}, deny("empty target")
	}
	for _, r := range raw {
		if r == '\\' || r <= 0x20 || r == 0x7f {
			return Target{}, deny("forbidden character in target")
		}
	}
	s := raw
	if !strings.HasPrefix(s, "http://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return Target{}, deny("unparsable target")
	}
	if u.Scheme != "http" || u.User != nil || u.Opaque != "" {
		return Target{}, deny("scheme, userinfo or opaque form not allowed")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "::1" {
		return Target{}, deny("host must be literal 127.0.0.1 or ::1")
	}
	portStr := u.Port()
	if portStr == "" {
		return Target{}, deny("port required")
	}
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return Target{}, deny("port must be decimal digits")
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Target{}, deny("port out of range")
	}
	hostForm := host
	if host == "::1" {
		hostForm = "[::1]"
	}
	if u.Host != hostForm+":"+portStr {
		return Target{}, deny("non-canonical host form")
	}
	hp := hostForm + ":" + strconv.Itoa(port)
	out := "http://" + hp + u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return Target{HostPort: hp, URL: out}, nil
}

// Guard 는 allow-list 대조(Check)와 안전한 GET(Fetch)을 제공한다.
type Guard struct {
	allow    map[string]struct{}
	maxBytes int64
	timeout  time.Duration
}

// NewGuard 는 allow-list(정규 HostPort)와 상한으로 Guard 를 만든다. 빈 목록은 전부 거부한다.
func NewGuard(allow []string, maxBytes int64, timeout time.Duration) (*Guard, error) {
	g := &Guard{allow: make(map[string]struct{}, len(allow)), maxBytes: maxBytes, timeout: timeout}
	for _, a := range allow {
		t, err := ParseTarget(a)
		if err != nil || t.HostPort != a {
			return nil, fmt.Errorf("netguard: invalid allow-list entry %q", a)
		}
		g.allow[a] = struct{}{}
	}
	if g.maxBytes <= 0 {
		g.maxBytes = defaultMaxBytes
	}
	if g.timeout <= 0 {
		g.timeout = defaultTimeout
	}
	return g, nil
}

// Check 는 hostPort 가 allow-list 에 정확히 있는지 확인한다. 소켓을 열지 않는다.
func (g *Guard) Check(hostPort string) error {
	if _, ok := g.allow[hostPort]; !ok {
		return deny("host:port not in allow-list")
	}
	return nil
}

// Fetch 는 allow-list 에 있는 대상에만 GET 을 보내고 본문을 반환한다.
func (g *Guard) Fetch(ctx context.Context, t Target) ([]byte, error) {
	if err := g.Check(t.HostPort); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != t.HostPort {
				return nil, deny("dial address differs from checked target")
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   g.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return deny("redirect not allowed")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return nil, domain.NewError(domain.ReasonInternalError, stageName, "build request", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, g.mapErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, deny("redirect response not allowed")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, g.maxBytes+1))
	if err != nil {
		return nil, g.mapErr(err)
	}
	if int64(len(body)) > g.maxBytes {
		return nil, domain.NewError(domain.ReasonToolLimitExceeded, stageName, "response exceeds byte limit", nil)
	}
	return body, nil
}

func (g *Guard) mapErr(err error) error {
	var de *domain.Error
	if errors.As(err, &de) {
		return de
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return domain.NewError(domain.ReasonToolLimitExceeded, stageName, "request timed out", err)
	}
	return domain.NewError(domain.ReasonInternalError, stageName, "fetch failed", err)
}
