package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/proxy"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// asAdmin returns a copy of the request whose context carries an admin role +
// super-admin, mimicking what AdminAuth installs so mutator handlers run.
func asAdmin(r *http.Request) *http.Request {
	ctx := iam.WithRole(r.Context(), iam.RoleAdmin)
	ctx = iam.WithSuperAdmin(ctx, true)
	return r.WithContext(ctx)
}

// newTestServer builds a real *Server over miniredis with no PostgreSQL-backed
// deps (catalog/users/audit nil), exercising NewServer + registerRoutes +
// ServeHTTP and the store-backed handlers end-to-end.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	log := logger.New("error")
	gw, err := proxy.New([]config.RouteConfig{{Path: "/x", Upstreams: []string{"http://127.0.0.1:9"}}}, config.MultitenancyConfig{}, log)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return NewServer(st, log, config.GatewayConfig{}, gw, nil, nil, nil, nil, nil, nil)
}

func TestServer_HealthAndReadiness(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{"/health", "/readyz"} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

func TestServer_PrometheusExposition(t *testing.T) {
	s := newTestServer(t)
	// Seed a couple of counters through the same store the handler reads.
	s.store.IncrMetric(t.Context(), "blocked_sqli")
	s.store.IncrMetric(t.Context(), "blocked_sqli")
	s.store.IncrMetric(t.Context(), "requests_passed_waf")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("content-type = %q, want prometheus text", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "aegis_blocked_sqli 2") {
		t.Errorf("prometheus output missing seeded counter:\n%s", body)
	}
}

func TestServer_StoreBackedHandlers(t *testing.T) {
	s := newTestServer(t)
	// JSON admin endpoints that read only the store should answer 200.
	for _, path := range []string{"/api/metrics", "/api/inventory", "/api/blocked-ips", "/api/block-log"} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

// TestServer_DiscoveryHandlersNoCatalog exercises the nil-catalog branch of the
// discovery handlers (the test server has no PostgreSQL catalog). Auth itself is
// the AdminAuth middleware's job (covered in the middleware package); here we
// only assert each handler runs without panicking and returns a sane status.
func TestServer_DiscoveryHandlersNoCatalog(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{
		"/api/catalog", "/api/consumers", "/api/posture/summary",
		"/api/effectiveness", "/api/findings", "/api/report",
	} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodGet, path, nil)))
		if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusOK {
			t.Errorf("GET %s with no catalog = %d, want 503 or 200", path, rec.Code)
		}
	}
}

func TestServer_BlockIPRoundTrip(t *testing.T) {
	s := newTestServer(t)
	// POST a block, then confirm it surfaces in the blocked-ips list.
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, asAdmin(httptest.NewRequest(http.MethodPost, "/api/blocked-ips",
		strings.NewReader(`{"ip":"203.0.113.7"}`))))
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/blocked-ips = %d (body: %s)", rec.Code, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/blocked-ips", nil))
	if !strings.Contains(rec2.Body.String(), "203.0.113.7") {
		t.Errorf("blocked IP not listed: %s", rec2.Body.String())
	}
}
