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
