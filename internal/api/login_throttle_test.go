package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLogin_ThrottlesAfterRepeatedFailures verifies the per-IP brute-force gate
// in login() flips to 429 + Retry-After after loginBruteforceLimit consecutive
// failures within the window. Backed by an in-memory Redis (miniredis) so it
// runs in plain `go test ./...` with no external services.
func TestLogin_ThrottlesAfterRepeatedFailures(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	// Use a unique RemoteAddr so the counter is isolated.
	ip := "203.0.113.117:1111"

	post := func() *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"secret": "wrong"})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
		r.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.login(rec, r)
		return rec
	}

	// First N attempts return 401 — credentials wrong but gate not yet tripped.
	for i := 1; i <= loginBruteforceLimit; i++ {
		if code := post().Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, code)
		}
	}
	// One more: gate now denies before doing crypto work.
	rec := post()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", loginBruteforceLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header must be set on throttle response")
	}
}
