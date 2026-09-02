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

// trusted_proxies is the switch that decides whether X-Forwarded-For is
// believed, and every per-IP control reads the answer — RealIP, the rate
// limiter, the IP guard, behavioural scoring, and the consumer identity BOLA
// counts enumeration against when the caller presents no JWT or API key. Trust a
// whole network and any host in it can pick a different client address per
// request, which switches those controls off rather than merely falsifying them.
func TestOverlyBroadTrustedProxies(t *testing.T) {
	cases := []struct {
		cidrs []string
		want  []string
	}{
		// Exact addresses: the documented shape, nothing to report.
		{[]string{"10.10.1.5/32", "10.10.1.6/32"}, nil},
		// A small pool is still specific enough to be deliberate.
		{[]string{"192.0.2.0/28", "192.0.2.16/24"}, nil},
		// The ranges the configuration reference calls out by name.
		{[]string{"10.0.0.0/8"}, []string{"10.0.0.0/8"}},
		{[]string{"172.16.0.0/16", "203.0.113.9/32"}, []string{"172.16.0.0/16"}},
		// IPv6: a /64 is one subnet an operator assigns; wider is a network.
		{[]string{"2001:db8::/64"}, nil},
		{[]string{"2001:db8::/32"}, []string{"2001:db8::/32"}},
	}
	for _, c := range cases {
		nets, err := ParseTrustedProxies(c.cidrs)
		if err != nil {
			t.Fatalf("ParseTrustedProxies(%v): %v", c.cidrs, err)
		}
		got := OverlyBroadTrustedProxies(nets)
		if len(got) != len(c.want) {
			t.Errorf("OverlyBroadTrustedProxies(%v) = %v, want %v", c.cidrs, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("OverlyBroadTrustedProxies(%v) = %v, want %v", c.cidrs, got, c.want)
				break
			}
		}
	}
}
