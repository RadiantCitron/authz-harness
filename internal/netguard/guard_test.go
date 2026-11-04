package netguard_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"authz-harness/internal/domain"
	"authz-harness/internal/netguard"
)

func hostPort(t *testing.T, s *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func counting(h http.HandlerFunc) (*httptest.Server, *int32) {
	var n int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		h(w, r)
	}))
	return s, &n
}

func wantReason(t *testing.T, err error, r domain.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", r)
	}
	if got := domain.ReasonFromError(err, ""); got != r {
		t.Fatalf("expected %s, got %s (%v)", r, got, err)
	}
	if code := domain.ExitCodeFromError(err, 0); r != domain.ReasonInternalError && code != domain.ExitAuthzDenied {
		t.Fatalf("expected exit 12, got %d", code)
	}
}

// TC-020-01
func TestParseTarget_Accept(t *testing.T) {
	cases := []struct{ in, hp string }{
		{"http://127.0.0.1:18080/status?x=1#f", "127.0.0.1:18080"},
		{"127.0.0.1:18080", "127.0.0.1:18080"},
		{"http://[::1]:18080/", "[::1]:18080"},
	}
	for _, c := range cases {
		got, err := netguard.ParseTarget(c.in)
		if err != nil || got.HostPort != c.hp {
			t.Errorf("ParseTarget(%q) = %+v, %v; want HostPort %s", c.in, got, err, c.hp)
			continue
		}
		if strings.Contains(got.URL, "#") {
			t.Errorf("fragment kept: %s", got.URL)
		}
	}
}

// TC-020-02
func TestParseTarget_Deny(t *testing.T) {
	for _, in := range []string{
		"http://127.0.0.1:18080@evil/", "http://evil@127.0.0.1:18080/", "http://2130706433:80/",
		"http://0x7f000001:80/", "http://127.1:80/", "http://localhost:80/", "http://127.0.0.1.:80/",
		"https://127.0.0.1:443/", "http://127.0.0.1/", "http://127.0.0.1:0/", `http:\\127.0.0.1:80\`,
		"http://0177.0.0.1:80/", "http://[::ffff:127.0.0.1]:80/", "http://[0:0:0:0:0:0:0:1]:80/",
		"HTTP://127.0.0.1:80/", "file:///etc/passwd", "http://127.0.0.1:+80/", "http://127.0.0.1:99999/",
		"http://127.0.0.1:80/a b", "",
	} {
		_, err := netguard.ParseTarget(in)
		wantReason(t, err, domain.ReasonEgressDenied)
	}
}

// TC-020-03
func TestFetch_Allowed(t *testing.T) {
	s, n := counting(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello")) })
	defer s.Close()
	g, err := netguard.NewGuard([]string{hostPort(t, s)}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := netguard.ParseTarget(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := g.Fetch(context.Background(), tg)
	if err != nil || string(body) != "hello" || atomic.LoadInt32(n) != 1 {
		t.Fatalf("body=%q err=%v requests=%d", body, err, atomic.LoadInt32(n))
	}
}

// TC-020-04
func TestFetch_NotInAllowList(t *testing.T) {
	s, n := counting(func(w http.ResponseWriter, r *http.Request) {})
	defer s.Close()
	g, err := netguard.NewGuard([]string{"127.0.0.1:1"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantReason(t, g.Check(hostPort(t, s)), domain.ReasonEgressDenied)
	tg, _ := netguard.ParseTarget(s.URL)
	_, err = g.Fetch(context.Background(), tg)
	wantReason(t, err, domain.ReasonEgressDenied)
	if atomic.LoadInt32(n) != 0 {
		t.Fatal("server must not be contacted")
	}
	empty, _ := netguard.NewGuard(nil, 0, 0)
	wantReason(t, empty.Check("127.0.0.1:1"), domain.ReasonEgressDenied)
}

func TestNewGuard_RejectsBadEntry(t *testing.T) {
	for _, a := range []string{"localhost:80", "127.0.0.1", "http://127.0.0.1:80", "127.0.0.1:080"} {
		if _, err := netguard.NewGuard([]string{a}, 0, 0); err == nil {
			t.Errorf("allow entry %q must be rejected", a)
		}
	}
}

// TC-020-05
func TestFetch_RedirectDenied(t *testing.T) {
	b, nb := counting(func(w http.ResponseWriter, r *http.Request) {})
	defer b.Close()
	a, _ := counting(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, b.URL, http.StatusFound) })
	defer a.Close()
	g, _ := netguard.NewGuard([]string{hostPort(t, a), hostPort(t, b)}, 0, 0)
	tg, _ := netguard.ParseTarget(a.URL)
	_, err := g.Fetch(context.Background(), tg)
	wantReason(t, err, domain.ReasonEgressDenied)
	if atomic.LoadInt32(nb) != 0 {
		t.Fatal("redirect target must not be contacted")
	}
}

// TC-020-06
func TestFetch_IgnoresProxyEnv(t *testing.T) {
	p, np := counting(func(w http.ResponseWriter, r *http.Request) {})
	defer p.Close()
	t.Setenv("HTTP_PROXY", p.URL)
	t.Setenv("http_proxy", p.URL)
	t.Setenv("NO_PROXY", "")
	s, _ := counting(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	defer s.Close()
	g, _ := netguard.NewGuard([]string{hostPort(t, s)}, 0, 0)
	tg, _ := netguard.ParseTarget(s.URL)
	if _, err := g.Fetch(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(np) != 0 {
		t.Fatal("proxy must not be used")
	}
}

// TC-020-07
func TestFetch_Limits(t *testing.T) {
	big, _ := counting(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 17))) })
	defer big.Close()
	g, _ := netguard.NewGuard([]string{hostPort(t, big)}, 16, 0)
	tg, _ := netguard.ParseTarget(big.URL)
	body, err := g.Fetch(context.Background(), tg)
	wantReason(t, err, domain.ReasonToolLimitExceeded)
	if body != nil {
		t.Fatal("body must not be returned")
	}

	slow, _ := counting(func(w http.ResponseWriter, r *http.Request) { time.Sleep(500 * time.Millisecond) })
	defer slow.Close()
	g2, _ := netguard.NewGuard([]string{hostPort(t, slow)}, 0, 100*time.Millisecond)
	tg2, _ := netguard.ParseTarget(slow.URL)
	body, err = g2.Fetch(context.Background(), tg2)
	wantReason(t, err, domain.ReasonToolLimitExceeded)
	if body != nil {
		t.Fatal("body must not be returned")
	}
}

// 검증한 Target 과 다른 주소로는 연결하지 않는다(T-8).
func TestFetch_ConnectFailureIsInternal(t *testing.T) {
	g, _ := netguard.NewGuard([]string{"127.0.0.1:1"}, 0, time.Second)
	tg, _ := netguard.ParseTarget("127.0.0.1:1")
	_, err := g.Fetch(context.Background(), tg)
	wantReason(t, err, domain.ReasonInternalError)
}
