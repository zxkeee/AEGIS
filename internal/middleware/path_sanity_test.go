package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func pathSanityStatus(t *testing.T, target string) int {
	t.Helper()
	_ = InitTrustedProxies(nil)
	h := PathSanity(fakeLogger{}, &fakeStore{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// The confirmed auth-exclude bypass vectors must all be rejected with 400.
func TestPathSanity_RejectsTraversal(t *testing.T) {
	bad := []string{
		"/public/..%2fsecret",
		"/public/%2e%2e/secret",
		"/public%2f..%2fsecret",
		"/public/..%5csecret",
		"/a/../b",
		"/a/b/..",
		"/..%2f..%2fetc/passwd",
		"/foo%5cbar",
	}
	for _, p := range bad {
		if code := pathSanityStatus(t, p); code != http.StatusBadRequest {
			t.Errorf("path %q: got %d, want 400", p, code)
		}
	}
}

// Legitimate paths (including dotfiles and single-dot, which are not traversal)
// must pass through untouched.
func TestPathSanity_AllowsBenign(t *testing.T) {
	good := []string{
		"/public/x",
		"/api/v1/users/123",
		"/.well-known/openid-configuration",
		"/a/./b",
		"/files/report..pdf",
		"/search?q=union",
	}
	for _, p := range good {
		if code := pathSanityStatus(t, p); code != http.StatusOK {
			t.Errorf("benign path %q wrongly rejected: got %d, want 200", p, code)
		}
	}
}

// TestPathSanity_RejectsNormalisationBypasses pins three confirmed ways a
// request slipped past this filter and reached a different resource on the
// backend than the one the gateway made its auth decision about (reproduced
// against a running gateway, 2026-09-02 — each of these returned 200 on an
// "auth.exclude: /public" prefix and was forwarded to the backend verbatim).
func TestPathSanity_RejectsNormalisationBypasses(t *testing.T) {
	cases := map[string]string{
		// Java servlet containers strip ";..." from a segment, then resolve "..".
		"path parameter hiding a traversal segment": "/public/..;/orders",
		"path parameter with a value":               "/public/..;jsessionid=abc/orders",
		// Encoded ';' decodes to the same thing before this check runs.
		"encoded path parameter": "/public/..%3B/orders",
		// One decode leaves "%2e%2e"; a backend that decodes again sees "..".
		"double-encoded dot segment": "/public/%252e%252e/orders",
		"double-encoded separator":   "/public%252fadmin",
		// Overlong UTF-8: "/" to a decoder that accepts overlong forms.
		"overlong UTF-8 separator": "/public/..%c0%af/orders",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, raw, nil)
			if reason := unsafePath(r); reason == "" {
				t.Errorf("%s: accepted %q — the gateway and the backend can disagree about the target", name, raw)
			}
		})
	}
}

// The rejections above must not swallow ordinary paths. A literal '%' that is
// not a path-significant escape, a matrix parameter on a normal segment, and a
// filename that merely starts with dots all stay legal.
func TestPathSanity_AllowsBenignAfterBypassHardening(t *testing.T) {
	for _, raw := range []string{
		"/orders/50%25",      // a literal '%' (encoded), not an escape
		"/orders/AB%2541",    // double-encoded, but not a path-significant escape
		"/orders;v=2/items",  // matrix parameter on an ordinary segment
		"/files/..foo",       // filename starting with dots
		"/files/.hidden",     // dotfile
		"/a/./b",             // single-dot segment is harmless
		"/catalog/caf%C3%A9", // ordinary UTF-8
	} {
		t.Run(raw, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, raw, nil)
			if reason := unsafePath(r); reason != "" {
				t.Errorf("rejected benign path %q: %s", raw, reason)
			}
		})
	}
}
