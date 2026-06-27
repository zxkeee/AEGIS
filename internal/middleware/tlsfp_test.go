package middleware

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/tlsfp"
)

func TestCleanHeaders_StripsSpoofedJA3(t *testing.T) {
	var seen http.Header
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() })
	h := CleanHeaders()(next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-JA3-Fingerprint", "client-spoofed-fingerprint")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen.Get("X-JA3-Fingerprint") != "" {
		t.Fatal("spoofed X-JA3-Fingerprint reached the backend")
	}
}

func TestTLSFingerprint_InjectsFromContext(t *testing.T) {
	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-JA3-Fingerprint")
	})
	h := TLSFingerprint()(next)

	// Simulate the connection context the tlsfp.Registry would have populated.
	reg := tlsfp.NewRegistry()
	ctx := reg.ConnContext(context.Background(), &nopConn{})
	// No handshake captured: header stays unset.
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "" {
		t.Fatalf("expected empty fingerprint when none captured, got %q", seen)
	}
}

func TestTLSFingerprint_NoContextNoHeader(t *testing.T) {
	var present bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Ja3-Fingerprint"]
	})
	TLSFingerprint()(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if present {
		t.Fatal("no TLS context: header must not be set")
	}
}

func TestUpstreamFingerprint_TrustsFromTrustedProxy(t *testing.T) {
	_ = InitTrustedProxies([]string{"10.0.0.0/8"})
	defer InitTrustedProxies(nil) //nolint:errcheck

	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-JA3-Fingerprint")
	})
	cfg := config.BotConfig{TrustUpstreamJA3: true, UpstreamJA3Header: "Cf-Ja3-Hash"}
	h := UpstreamFingerprint(cfg)(next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:443" // trusted proxy (Cloudflare/origin)
	r.Header.Set("Cf-Ja3-Hash", "abc123")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen != "abc123" {
		t.Fatalf("trusted upstream JA3 not honoured: %q", seen)
	}
}

func TestUpstreamFingerprint_RejectsUntrustedPeer(t *testing.T) {
	_ = InitTrustedProxies([]string{"10.0.0.0/8"})
	defer InitTrustedProxies(nil) //nolint:errcheck

	var seen string
	var forwarded bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-JA3-Fingerprint")
		_, forwarded = r.Header["Cf-Ja3-Hash"]
	})
	cfg := config.BotConfig{TrustUpstreamJA3: true, UpstreamJA3Header: "Cf-Ja3-Hash"}
	h := UpstreamFingerprint(cfg)(next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:5555" // NOT a trusted proxy (direct client)
	r.Header.Set("Cf-Ja3-Hash", "spoofed")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen != "" {
		t.Fatalf("untrusted peer JA3 must be ignored, got %q", seen)
	}
	if forwarded {
		t.Fatal("upstream JA3 header must not reach the backend")
	}
}

func TestUpstreamFingerprint_DisabledPassthrough(t *testing.T) {
	var forwarded bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, forwarded = r.Header["Cf-Ja3-Hash"]
	})
	h := UpstreamFingerprint(config.BotConfig{TrustUpstreamJA3: false})(next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cf-Ja3-Hash", "x")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !forwarded {
		// Disabled = passthrough: it does not touch headers at all.
		t.Fatal("disabled middleware should not alter headers")
	}
}

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, nil }
func (nopConn) Write([]byte) (int, error)        { return 0, nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
