package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
)

// TestRouteGate_RunsInnerOnlyWhenEnabled verifies the core gate semantics: the
// wrapped control runs exactly when enabled(path) is true, otherwise the request
// passes straight through to next.
func TestRouteGate_RunsInnerOnlyWhenEnabled(t *testing.T) {
	innerRan := false
	inner := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			innerRan = true
			next.ServeHTTP(w, r)
		})
	}

	enabled := func(path string) bool { return path == "/gated" }
	h := RouteGate(enabled, inner)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Gated path -> inner runs.
	innerRan = false
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/gated", nil))
	if !innerRan {
		t.Fatal("inner control should run on a gated path")
	}

	// Ungated path -> inner skipped.
	innerRan = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/open", nil))
	if innerRan {
		t.Fatal("inner control must NOT run on an ungated path")
	}
}

// TestRouteGate_EnforcesPerRouteAuth is the regression test for the headline bug:
// auth is globally OFF, but a route sets require_auth: true. The posture engine
// reports the path as protected, and — with the gate — the data plane MUST also
// reject an unauthenticated request, while a non-overridden path stays open.
func TestRouteGate_EnforcesPerRouteAuth(t *testing.T) {
	requireAuth := true
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Enabled: false}, // globally OFF
		},
		Routes: []config.RouteConfig{
			{Path: "/secure", RequireAuth: &requireAuth},
			{Path: "/public"}, // no override -> inherits global (off)
		},
	}

	// Mirror buildHandlerChain: force-enable auth and gate it on the effective
	// AuthRequired control resolved from the same engine posture uses.
	authCfg := cfg.Security.Auth
	authCfg.Enabled = true
	forced := NewJWTAuth(authCfg, fakeLogger{}, &fakeStore{}).Middleware()

	postureEng := discovery.NewPostureEngine(cfg)
	authRequired := func(path string) bool {
		c, _ := postureEng.ControlsFor(path)
		return c.AuthRequired
	}
	gated := RouteGate(authRequired, forced)

	backendHit := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
	})
	h := gated(backend)

	// /secure WITHOUT a token: must be rejected before reaching the backend.
	backendHit = false
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secure", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/secure unauthenticated: want 401, got %d", rec.Code)
	}
	if backendHit {
		t.Fatal("/secure: backend was reached without authentication — enforcement gap")
	}

	// /public: no override, auth globally off -> passes through.
	backendHit = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public", nil))
	if !backendHit {
		t.Fatalf("/public: want passthrough to backend, got status %d", rec.Code)
	}
}
