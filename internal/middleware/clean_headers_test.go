package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// captureHeaders runs CleanHeaders around a handler that records the headers the
// backend would receive, for the given RemoteAddr and inbound headers.
func captureHeaders(remoteAddr string, in map[string]string) http.Header {
	var got http.Header
	h := CleanHeaders()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range in {
		r.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

// Identity headers a client must never forge are always stripped.
func TestCleanHeaders_StripsForgedIdentity(t *testing.T) {
	_ = InitTrustedProxies(nil)
	got := captureHeaders("203.0.113.7:5555", map[string]string{
		"X-Gateway-Subject": "attacker",
		"X-Gateway-Roles":   "admin",
		"X-JA3-Fingerprint": "deadbeef",
	})
	for _, h := range []string{"X-Gateway-Subject", "X-Gateway-Roles", "X-Ja3-Fingerprint"} {
		if got.Get(h) != "" {
			t.Errorf("%s should be stripped, got %q", h, got.Get(h))
		}
	}
}

// From an untrusted peer, the whole forwarding family is stripped and X-Real-IP
// is re-asserted to the real TCP peer — no client spoofing reaches the backend.
func TestCleanHeaders_UntrustedPeer_SanitisesForwarding(t *testing.T) {
	_ = InitTrustedProxies(nil) // nothing trusted

	got := captureHeaders("203.0.113.7:5555", map[string]string{
		"X-Real-IP":         "9.9.9.9",
		"X-Forwarded-For":   "1.2.3.4",
		"X-Forwarded-Host":  "evil.com",
		"X-Forwarded-Proto": "https",
		"True-Client-IP":    "1.1.1.1",
		"CF-Connecting-IP":  "2.2.2.2",
	})

	if got.Get("X-Forwarded-Host") != "" {
		t.Errorf("X-Forwarded-Host should be stripped, got %q", got.Get("X-Forwarded-Host"))
	}
	if got.Get("True-Client-IP") != "" || got.Get("CF-Connecting-IP") != "" {
		t.Error("client-IP override headers should be stripped")
	}
	// X-Real-IP must be re-asserted to the real peer, not the spoofed value.
	if got.Get("X-Real-IP") != "203.0.113.7" {
		t.Errorf("X-Real-IP = %q, want authoritative 203.0.113.7", got.Get("X-Real-IP"))
	}
	// X-Forwarded-For is deleted here (the proxy re-sets it); must not retain the
	// attacker value.
	if got.Get("X-Forwarded-For") == "1.2.3.4" {
		t.Error("attacker X-Forwarded-For must not survive")
	}
}

// From a trusted proxy the forwarding chain is authoritative and preserved.
func TestCleanHeaders_TrustedPeer_PreservesForwarding(t *testing.T) {
	if err := InitTrustedProxies([]string{"203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = InitTrustedProxies(nil) }()

	got := captureHeaders("203.0.113.7:5555", map[string]string{
		"X-Forwarded-For":  "1.2.3.4",
		"X-Forwarded-Host": "api.example.com",
	})

	if got.Get("X-Forwarded-For") != "1.2.3.4" {
		t.Errorf("trusted XFF should be preserved, got %q", got.Get("X-Forwarded-For"))
	}
	if got.Get("X-Forwarded-Host") != "api.example.com" {
		t.Errorf("trusted X-Forwarded-Host should be preserved, got %q", got.Get("X-Forwarded-Host"))
	}
}
