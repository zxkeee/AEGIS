package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
)

func tenantOf(t *testing.T, mt config.MultitenancyConfig, routes []config.RouteConfig, setup func(*http.Request)) (string, int) {
	t.Helper()
	var resolved string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved = TenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := TenantResolve(mt, routes, fakeLogger{}, &fakeStore{})(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if setup != nil {
		setup(r)
	}
	h.ServeHTTP(rec, r)
	return resolved, rec.Code
}

func TestTenant_DisabledPinsDefault(t *testing.T) {
	got, code := tenantOf(t, config.MultitenancyConfig{Enabled: false}, nil, nil)
	if code != http.StatusOK || got != config.DefaultTenant {
		t.Fatalf("disabled MT: tenant=%q code=%d, want default/200", got, code)
	}
}

func TestTenant_ResolvedByRoute(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{{ID: "acme"}}}
	routes := []config.RouteConfig{{Path: "/orders", TenantID: "acme"}}
	got, code := tenantOf(t, mt, routes, func(r *http.Request) { r.URL.Path = "/orders/42" })
	if code != http.StatusOK || got != "acme" {
		t.Fatalf("route resolve: tenant=%q code=%d, want acme/200", got, code)
	}
}

// TestTenant_AdjacentPathNotCaptured guards the segment-boundary match: a route
// "/orders" owned by acme must NOT capture "/ordersXYZ", which shares a raw
// prefix but is a different path. Without the boundary check that request would
// be mis-attributed to acme's tenant (wrong Redis/metrics/catalog isolation).
func TestTenant_AdjacentPathNotCaptured(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{{ID: "acme"}}}
	routes := []config.RouteConfig{{Path: "/orders", TenantID: "acme"}}
	got, code := tenantOf(t, mt, routes, func(r *http.Request) { r.URL.Path = "/ordersXYZ" })
	// No route and no host match → unresolved → 404, never silently acme.
	if code != http.StatusNotFound {
		t.Fatalf("adjacent path: tenant=%q code=%d, want unresolved/404", got, code)
	}
}

func TestTenant_ResolvedByHost(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{
		{ID: "globex", Hosts: []string{"globex.api.example"}},
	}}
	got, code := tenantOf(t, mt, nil, func(r *http.Request) {
		r.Host = "globex.api.example:8080"
		r.URL.Path = "/anything"
	})
	if code != http.StatusOK || got != "globex" {
		t.Fatalf("host resolve: tenant=%q code=%d, want globex/200", got, code)
	}
}

func TestTenant_HostRouteMismatchRejected(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{
		{ID: "acme", Hosts: []string{"acme.example"}},
		{ID: "globex"},
	}}
	routes := []config.RouteConfig{{Path: "/orders", TenantID: "globex"}}
	_, code := tenantOf(t, mt, routes, func(r *http.Request) {
		r.Host = "acme.example" // host says acme, route says globex
		r.URL.Path = "/orders/1"
	})
	if code != http.StatusNotFound {
		t.Fatalf("host/route mismatch: code=%d, want 404", code)
	}
}

func TestTenant_UnresolvedRejected(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{{ID: "acme"}}}
	_, code := tenantOf(t, mt, nil, func(r *http.Request) {
		r.Host = "unknown.example"
		r.URL.Path = "/no-route"
	})
	if code != http.StatusNotFound {
		t.Fatalf("unresolved tenant: code=%d, want 404", code)
	}
}

func TestTenant_StripsSpoofedHeader(t *testing.T) {
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Tenant-Id")
	})
	mt := config.MultitenancyConfig{Enabled: false}
	h := TenantResolve(mt, nil, fakeLogger{}, &fakeStore{})(next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Tenant-Id", "attacker-tenant")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != "" {
		t.Fatalf("spoofed X-Tenant-Id reached backend: %q", seen)
	}
}

func TestTenant_LongestPrefixWins(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{{ID: "a"}, {ID: "b"}}}
	routes := []config.RouteConfig{
		{Path: "/api", TenantID: "a"},
		{Path: "/api/orders", TenantID: "b"},
	}
	got, code := tenantOf(t, mt, routes, func(r *http.Request) { r.URL.Path = "/api/orders/1" })
	if code != http.StatusOK || got != "b" {
		t.Fatalf("longest-prefix: tenant=%q code=%d, want b/200", got, code)
	}
}

func TestRoutePrefix(t *testing.T) {
	cases := map[string]string{
		"/orders":         "/orders",
		"/orders/":        "/orders",
		"GET /orders":     "/orders",
		"example.com/api": "/api",
	}
	for in, want := range cases {
		if got := routePrefix(in); got != want {
			t.Errorf("routePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
