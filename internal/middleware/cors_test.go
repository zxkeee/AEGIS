package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
)

func corsHandler(cfg config.CORSConfig) http.Handler {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return CORS(cfg)(next)
}

func TestCORS_Disabled_Passthrough(t *testing.T) {
	h := corsHandler(config.CORSConfig{Enabled: false})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(rec, r)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disabled CORS must not set ACAO")
	}
}

func TestCORS_NoOrigin_Passthrough(t *testing.T) {
	h := corsHandler(config.CORSConfig{Enabled: true, AllowOrigins: []string{"https://app.example"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("same-origin request should pass without ACAO")
	}
}

func TestCORS_AllowedOrigin(t *testing.T) {
	h := corsHandler(config.CORSConfig{Enabled: true, AllowOrigins: []string{"https://app.example"}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://app.example")
	h.ServeHTTP(rec, r)
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("ACAO = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Fatal("per-origin response must Vary: Origin")
	}
}

func TestCORS_DisallowedPreflight_403(t *testing.T) {
	h := corsHandler(config.CORSConfig{Enabled: true, AllowOrigins: []string{"https://app.example"}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed preflight: got %d, want 403", rec.Code)
	}
}

func TestCORS_Wildcard(t *testing.T) {
	h := corsHandler(config.CORSConfig{Enabled: true, AllowOrigins: []string{"*"}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://anything.example")
	h.ServeHTTP(rec, r)
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("wildcard must echo *")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight should be 204, got %d", rec.Code)
	}
}

func TestSecurityHeaders_SetsHardeningHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	SecurityHeaders()(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}
