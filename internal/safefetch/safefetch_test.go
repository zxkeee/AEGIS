package safefetch

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func redirTo(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return &http.Request{URL: u}
}

// Redirect now covers the two things a dialer cannot see: the scheme, and how
// many hops have happened. The address is checked where the connection is
// actually made — see TestClient_RefusesToConnectToLoopback, which proves that
// half by trying it.
func TestRedirect_SchemeAndHops(t *testing.T) {
	refused := []struct{ name, url string }{
		{"plaintext downgrade", "http://idp.example.com/jwks"},
		{"no scheme at all", "//idp.example.com/jwks"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			if err := Redirect("jwks", redirTo(t, c.url), nil); err == nil {
				t.Errorf("%s was followed", c.url)
			}
		})
	}

	if err := Redirect("jwks", redirTo(t, "https://idp.example.com/keys"), nil); err != nil {
		t.Errorf("an ordinary https redirect was refused: %v", err)
	}

	// The hop cap bounds a redirect loop between two https hosts, which the
	// scheme check alone would follow forever.
	via := make([]*http.Request, maxHops)
	if err := Redirect("jwks", redirTo(t, "https://idp.example.com/keys"), via); err == nil {
		t.Error("a sixth hop was followed; a redirect loop is unbounded")
	}
}

// The control that matters, exercised by actually trying to connect.
//
// A live server is started on loopback and the client is pointed at it by IP
// and by every name that used to slip past the string check. Each attempt must
// fail at the dialer, and the server must record zero requests — the previous
// implementation reached it every time.
func TestClient_RefusesToConnectToLoopback(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srv.URL, err)
	}

	// Every one of these resolves or parses to loopback. The first is the plain
	// address; the rest are the forms that defeated the string check.
	for _, host := range []string{
		"127.0.0.1",
		"localhost",
		"localhost.", // trailing dot: the fully-qualified form
		"2130706433", // decimal
		"127.1",      // short form
		"0x7f.0.0.1", // hexadecimal
		"[::1]",
	} {
		t.Run(host, func(t *testing.T) {
			c := Client("probe", 5*time.Second)
			resp, err := c.Get("http://" + host + ":" + port + "/")
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("connected to %s — an internal address was reached", host)
			}
			if !strings.Contains(err.Error(), "probe:") {
				// Some of these fail at resolution on some platforms, which is
				// also a refusal — but say which, so a passing test cannot hide
				// behind an unrelated error.
				t.Logf("refused before the dialer: %v", err)
			}
		})
	}

	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the loopback server was reached %d times", n)
	}
}

// And it must still reach an ordinary destination, or the control is just an
// outage. A public address is used without sending a request: the dial decision
// is what is under test, so the connection is closed immediately.
func TestClient_AllowsAPublicAddress(t *testing.T) {
	c := Client("probe", 3*time.Second)
	_, err := c.Get("https://93.184.216.34/")
	if err != nil && strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("a public address was refused by the policy: %v", err)
	}
	// Any other error (no network in CI, TLS name mismatch, timeout) is fine:
	// the policy allowed the dial, which is the assertion.
}
