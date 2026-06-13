package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIP_NoTrustedProxies_UsesRemoteAddr(t *testing.T) {
	if err := InitTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4") // must be ignored
	if got := RealIP(r); got != "203.0.113.5" {
		t.Fatalf("RealIP = %q, want 203.0.113.5 (XFF must be ignored without trusted proxies)", got)
	}
}

func TestRealIP_TrustedProxy_ReturnsClient(t *testing.T) {
	if err := InitTrustedProxies([]string{"10.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := RealIP(r); got != "1.2.3.4" {
		t.Fatalf("RealIP = %q, want 1.2.3.4", got)
	}
}

func TestRealIP_PrefixSpoofingResisted(t *testing.T) {
	// An attacker prepends a fake IP to XFF. Walking right-to-left and stopping at
	// the first untrusted hop must return the real client, not the spoofed prefix.
	if err := InitTrustedProxies([]string{"10.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 1.2.3.4")
	if got := RealIP(r); got != "1.2.3.4" {
		t.Fatalf("RealIP = %q, want 1.2.3.4 (spoofed prefix must be ignored)", got)
	}
}

func TestInitTrustedProxies_RejectsInvalid(t *testing.T) {
	if err := InitTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid CIDR/IP")
	}
}
