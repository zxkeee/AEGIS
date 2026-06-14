package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
)

func adminHandler(st Store) http.Handler {
	_ = InitTrustedProxies(nil)
	cfg := config.GatewayConfig{AdminAuth: true, AdminSecret: testSecret}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return AdminAuth(cfg, fakeLogger{}, st)(next)
}

func doAdmin(h http.Handler, method, path string, mutate func(*http.Request)) int {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "1.2.3.4:1"
	if mutate != nil {
		mutate(r)
	}
	h.ServeHTTP(rec, r)
	return rec.Code
}

func TestAdmin_BearerValid(t *testing.T) {
	h := adminHandler(&fakeStore{})
	code := doAdmin(h, http.MethodGet, "/api/metrics", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+testSecret)
	})
	if code != http.StatusOK {
		t.Fatalf("valid bearer: got %d, want 200", code)
	}
}

func TestAdmin_BearerWrong(t *testing.T) {
	h := adminHandler(&fakeStore{})
	code := doAdmin(h, http.MethodGet, "/api/metrics", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer wrong")
	})
	if code != http.StatusForbidden {
		t.Fatalf("wrong bearer: got %d, want 403", code)
	}
}

func TestAdmin_NoAuth(t *testing.T) {
	if code := doAdmin(adminHandler(&fakeStore{}), http.MethodGet, "/api/metrics", nil); code != http.StatusUnauthorized {
		t.Fatalf("no auth: got %d, want 401", code)
	}
}

func TestAdmin_LoginRouteIsPublic(t *testing.T) {
	if code := doAdmin(adminHandler(&fakeStore{}), http.MethodPost, "/api/login", nil); code != http.StatusOK {
		t.Fatalf("/api/login should be public: got %d, want 200", code)
	}
}

func TestAdmin_SessionCookie_GET(t *testing.T) {
	st := &fakeStore{sessions: map[string]string{"sess-1": "csrf-1"}}
	code := doAdmin(adminHandler(st), http.MethodGet, "/api/metrics", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "sess-1"})
	})
	if code != http.StatusOK {
		t.Fatalf("valid session GET: got %d, want 200", code)
	}
}

func TestAdmin_SessionCookie_MutationRequiresCSRF(t *testing.T) {
	st := &fakeStore{sessions: map[string]string{"sess-1": "csrf-1"}}
	// POST without CSRF header must be rejected.
	code := doAdmin(adminHandler(st), http.MethodPost, "/api/blocked-ips", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "sess-1"})
	})
	if code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF: got %d, want 403", code)
	}
}

func TestAdmin_SessionCookie_MutationWithCSRF(t *testing.T) {
	st := &fakeStore{sessions: map[string]string{"sess-1": "csrf-1"}}
	code := doAdmin(adminHandler(st), http.MethodPost, "/api/blocked-ips", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "sess-1"})
		r.Header.Set(CSRFHeader, "csrf-1")
	})
	if code != http.StatusOK {
		t.Fatalf("mutation with correct CSRF: got %d, want 200", code)
	}
}

func TestAdmin_SessionCookie_Invalid(t *testing.T) {
	st := &fakeStore{sessions: map[string]string{}}
	code := doAdmin(adminHandler(st), http.MethodGet, "/api/metrics", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "nonexistent"})
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("invalid session: got %d, want 401", code)
	}
}
