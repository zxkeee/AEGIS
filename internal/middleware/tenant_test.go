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

// TestTenant_CaseInsensitiveRouteMatch is a regression test for a residual
// variant of the segment-boundary bypass TestTenant_AdjacentPathNotCaptured
// covers: a backend that routes case-insensitively would let a case-varied
// path ("/Orders", "/ORDERS") dodge the "/orders" route and fall through to
// unresolved (or, with an overlapping shorter route, to the WRONG tenant) —
// the same class already fixed in posture.go/abuse.go's BFLA check.
func TestTenant_CaseInsensitiveRouteMatch(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{{ID: "acme"}}}
	routes := []config.RouteConfig{{Path: "/orders", TenantID: "acme"}}
	for _, p := range []string{"/orders/42", "/Orders/42", "/ORDERS/42"} {
		got, code := tenantOf(t, mt, routes, func(r *http.Request) { r.URL.Path = p })
		if code != http.StatusOK || got != "acme" {
			t.Fatalf("path %q: tenant=%q code=%d, want acme/200 (case must not defeat route→tenant matching)", p, got, code)
		}
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

// When two tenants share a path, the path cannot identify either of them and
// the Host must decide. Before this, the shared prefix stayed in the model-B
// route table, so whichever route sorted first won the lookup and every OTHER
// tenant's request failed the host/route agreement check with a 404 — making
// the shared-path routing the proxy supports unreachable in the data plane.
func TestTenant_SharedPathResolvedByHost(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{
		{ID: "acme", Hosts: []string{"acme.example"}},
		{ID: "globex", Hosts: []string{"globex.example"}},
	}}
	routes := []config.RouteConfig{
		{Path: "/orders", TenantID: "acme"},
		{Path: "/orders", TenantID: "globex"},
	}
	for host, want := range map[string]string{"acme.example": "acme", "globex.example": "globex"} {
		got, code := tenantOf(t, mt, routes, func(r *http.Request) {
			r.URL.Path = "/orders/42"
			r.Host = host
		})
		if code != http.StatusOK || got != want {
			t.Fatalf("Host %q: tenant=%q code=%d, want %s/200", host, got, code, want)
		}
	}
	// An unknown Host on a shared path is genuinely unattributable — resolving
	// it to either tenant would be a cross-tenant leak.
	if _, code := tenantOf(t, mt, routes, func(r *http.Request) {
		r.URL.Path = "/orders/42"
		r.Host = "stranger.example"
	}); code != http.StatusNotFound {
		t.Fatalf("unknown Host on a shared path: code=%d, want 404", code)
	}
}

// A longer path claimed by a single tenant still resolves by route, even when a
// shorter prefix of it is shared — the ambiguity is per-prefix, not global.
func TestTenant_UnsharedLongerPathStillResolvesByRoute(t *testing.T) {
	mt := config.MultitenancyConfig{Enabled: true, Tenants: []config.TenantConfig{
		{ID: "acme", Hosts: []string{"acme.example"}},
		{ID: "globex", Hosts: []string{"globex.example"}},
	}}
	routes := []config.RouteConfig{
		{Path: "/orders", TenantID: "acme"},
		{Path: "/orders", TenantID: "globex"},
		{Path: "/orders/legacy", TenantID: "acme"},
	}
	got, code := tenantOf(t, mt, routes, func(r *http.Request) {
		r.URL.Path = "/orders/legacy/7"
		r.Host = "acme.example"
	})
	if code != http.StatusOK || got != "acme" {
		t.Fatalf("unshared longer path: tenant=%q code=%d, want acme/200", got, code)
	}
}
