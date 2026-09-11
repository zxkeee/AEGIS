package middleware

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func redirTo(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return &http.Request{URL: u}
}

// config.Validate pins these URLs to https. Without a redirect policy that pin
// evaporates at the first 302 — the default client follows ten hops, including
// to http:// and to internal addresses. For the JWKS document, which is the
// trust root for every RSA/ECDSA token, that is a full authentication bypass.
func TestSafeRedirect(t *testing.T) {
	refused := []struct{ name, url string }{
		{"plaintext downgrade", "http://idp.example.com/jwks"},
		{"loopback by name", "https://localhost/jwks"},
		{"loopback by address", "https://127.0.0.1/jwks"},
		{"cloud metadata", "https://169.254.169.254/latest/meta-data/"},
		{"private range", "https://10.0.0.5/jwks"},
		{"private range 192.168", "https://192.168.1.1/jwks"},
		{"ipv6 loopback", "https://[::1]/jwks"},
	}
	for _, tc := range refused {
		if err := safeRedirect("jwks", redirTo(t, tc.url), nil); err == nil {
			t.Errorf("%s: %s was followed", tc.name, tc.url)
		} else if !strings.Contains(err.Error(), "jwks") {
			t.Errorf("%s: the error should name the caller, got %v", tc.name, err)
		}
	}

	// A public https target is the ordinary case and must still work.
	if err := safeRedirect("jwks", redirTo(t, "https://idp.example.com/keys"), nil); err != nil {
		t.Errorf("an ordinary https redirect was refused: %v", err)
	}

	// The hop cap bounds a redirect loop.
	via := make([]*http.Request, 5)
	if err := safeRedirect("jwks", redirTo(t, "https://idp.example.com/keys"), via); err == nil {
		t.Error("a sixth hop was followed; a redirect loop is unbounded")
	}
}

// The threat feed's policy is the same one, so a change to either cannot
// silently diverge.
func TestCheckFeedRedirect_UsesTheSharedPolicy(t *testing.T) {
	if err := checkFeedRedirect(redirTo(t, "http://feed.example.com/list"), nil); err == nil {
		t.Error("the feed followed a plaintext redirect")
	}
	if err := checkFeedRedirect(redirTo(t, "https://169.254.169.254/"), nil); err == nil {
		t.Error("the feed followed a redirect to cloud metadata")
	}
	if err := checkFeedRedirect(redirTo(t, "https://feed.example.com/list"), nil); err != nil {
		t.Errorf("an ordinary https redirect was refused: %v", err)
	}
}
