package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"
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

// TestAdmin_RateLimitWrapsAuth locks in the chain ordering from main.go: the
// admin rate limiter must sit OUTSIDE AdminAuth so unauthenticated brute-force /
// DDoS traffic is throttled. If the limiter were inside AdminAuth (the previous
// bug) every bad-credential request would short-circuit at 401/403 and the
// limiter would never run, so 429 would never appear.
func TestAdmin_RateLimitWrapsAuth(t *testing.T) {
	_ = InitTrustedProxies(nil)
	var n int64
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) {
		n++
		return n, nil
	}}
	cfg := config.GatewayConfig{AdminAuth: true, AdminSecret: testSecret}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rl := config.RateLimitConfig{Enabled: true, Requests: 3, Window: time.Minute}
	// Same nesting as cmd/gateway/main.go: RateLimit outermost, then AdminAuth.
	h := Chain(next, RateLimit(rl, "test", fakeLogger{}, st), AdminAuth(cfg, fakeLogger{}, st))

	var got429 bool
	for i := 0; i < 6; i++ {
		// Unauthenticated request (no bearer, no cookie): AdminAuth alone would
		// answer 401 every time. We assert the limiter still trips to 429.
		code := doAdmin(h, http.MethodGet, "/api/whatever", nil)
		if code == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("unauthenticated flood never hit 429 — rate limiter is not wrapping AdminAuth")
	}
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

// — Phase 4: tenant/role context propagation + viewer RBAC —

// captureCtxHandler exposes the request context to the test so we can assert
// what AdminAuth put into it.
func captureCtxHandler(t *testing.T, st Store) (http.Handler, *iam.Role, *string) {
	t.Helper()
	var role iam.Role
	var tid string
	cfg := config.GatewayConfig{AdminAuth: true, AdminSecret: testSecret}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role = iam.FromContext(r.Context())
		tid = tenant.From(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	return AdminAuth(cfg, fakeLogger{}, st)(next), &role, &tid
}

func TestAdmin_SessionThreadsTenantAndRole(t *testing.T) {
	st := &fakeStore{sessionFull: map[string]iam.Session{
		"sess-1": {CSRF: "csrf-1", TenantID: "acme", Role: iam.RoleAdmin},
	}}
	h, role, tid := captureCtxHandler(t, st)
	code := doAdmin(h, http.MethodGet, "/api/metrics", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "sess-1"})
	})
	if code != http.StatusOK || *role != iam.RoleAdmin || *tid != "acme" {
		t.Fatalf("tenant/role not threaded: code=%d role=%q tid=%q", code, *role, *tid)
	}
}

func TestAdmin_BearerThreadsDefaultTenantAndAdmin(t *testing.T) {
	h, role, tid := captureCtxHandler(t, &fakeStore{})
	code := doAdmin(h, http.MethodGet, "/api/metrics", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+testSecret)
	})
	if code != http.StatusOK || *role != iam.RoleAdmin || *tid != tenant.Default {
		t.Fatalf("bearer ctx wrong: code=%d role=%q tid=%q", code, *role, *tid)
	}
}

func TestAdmin_ViewerCanReadButNotMutate(t *testing.T) {
	st := &fakeStore{sessionFull: map[string]iam.Session{
		"sess-v": {CSRF: "csrf-v", TenantID: "acme", Role: iam.RoleViewer},
	}}
	h := adminHandler(st)

	// GET succeeds (viewer can read).
	if code := doAdmin(h, http.MethodGet, "/api/metrics", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "sess-v"})
	}); code != http.StatusOK {
		t.Fatalf("viewer GET: got %d, want 200", code)
	}

	// POST with valid CSRF still rejected — role gate, not CSRF gate.
	code := doAdmin(h, http.MethodPost, "/api/blocked-ips", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "sess-v"})
		r.Header.Set(CSRFHeader, "csrf-v")
	})
	if code != http.StatusForbidden {
		t.Fatalf("viewer POST must be 403, got %d", code)
	}
}
