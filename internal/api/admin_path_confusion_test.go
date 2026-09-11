package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// AdminAuth decides what is public by comparing r.URL.Path against a fixed
// list, and http.ServeMux decides what to run after its own normalisation.
// Two different views of the same string, one in front of the other: if they
// ever disagree about which path this is, something public routes to something
// that is not.
//
// This drives the real pair — AdminAuth wrapped around the real mux — with the
// shapes that make a path mean two things, and requires that nothing sensitive
// is reached without credentials.
func TestAdminAuth_PathConfusionCannotReachAProtectedHandler(t *testing.T) {
	s := newTestServer(t)
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

	cfg := config.GatewayConfig{AdminAuth: true, AdminSecret: "a-strong-admin-secret-32-chars!!"}
	h := middleware.AdminAuth(cfg, logger.New("error"), st, nil)(s)

	// Every one of these must NOT be served as a protected handler would be.
	// 200 here means the request reached something behind the auth gate.
	probes := []struct{ name, path string }{
		{"dot segment", "/api/./metrics"},
		{"parent traversal", "/api/catalog/../metrics"},
		{"escape from the public asset prefix", "/assets/../api/metrics"},
		{"escape via encoded traversal", "/assets/%2e%2e/api/metrics"},
		{"double slash", "//api/metrics"},
		{"triple slash", "///api/metrics"},
		{"encoded separator", "/api%2fmetrics"},
		{"trailing dot segment", "/api/metrics/."},
		{"public path with a suffix", "/healthz/../api/metrics"},
		{"login prefix confusion", "/api/login/../metrics"},
		{"case variation", "/API/METRICS"},
		{"semicolon parameter", "/api/metrics;foo=bar"},
		{"trailing slash on a public path", "/health/"},
	}

	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			switch rec.Code {
			case http.StatusUnauthorized, http.StatusForbidden:
				// Refused at the gate.
			case http.StatusNotFound, http.StatusMethodNotAllowed:
				// Routed nowhere.
			case http.StatusMovedPermanently, http.StatusPermanentRedirect,
				http.StatusTemporaryRedirect, http.StatusFound:
				// The mux normalised the path and bounced it back to the client.
				// That is only safe if the place it points at has to pass the
				// gate on its own merits — so follow it and require exactly that.
				// Trusting the status code alone would accept a redirect that
				// lands somewhere already past the gate.
				loc := rec.Header().Get("Location")
				if loc == "" {
					t.Fatalf("GET %s = %d with no Location", p.path, rec.Code)
				}
				rec2 := httptest.NewRecorder()
				h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, loc, nil))
				if rec2.Code != http.StatusUnauthorized && rec2.Code != http.StatusForbidden {
					t.Errorf("GET %s redirected to %s, which answered %d instead of refusing",
						p.path, loc, rec2.Code)
				}
			default:
				t.Errorf("GET %s = %d; a protected handler was reachable without credentials\nbody: %.200s",
					p.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// AdminAuth decides public/private from the path alone, with no regard to
// method, while the mux routes on both. A public path reached with a method
// nobody registered must not fall through to something else — in particular
// not to the SPA fallback, which is registered for GET and would otherwise be
// the handler of last resort for anything.
func TestAdminAuth_PublicPathsAreNotPublicForEveryMethod(t *testing.T) {
	s := newTestServer(t)
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

	cfg := config.GatewayConfig{AdminAuth: true, AdminSecret: "a-strong-admin-secret-32-chars!!"}
	h := middleware.AdminAuth(cfg, logger.New("error"), st, nil)(s)

	public := []string{"/health", "/readyz", "/api/console/env", "/api/login",
		"/api/auth/oidc/login", "/api/auth/oidc/callback"}
	methods := []string{http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead}

	for _, path := range public {
		for _, m := range methods {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(m, path, nil))
			// 2xx is only acceptable where that method is genuinely registered
			// for that path (POST /api/login, and HEAD, which net/http serves
			// from the GET handler).
			if rec.Code < 300 {
				if (path == "/api/login" && m == http.MethodPost) || m == http.MethodHead {
					continue
				}
				t.Errorf("%s %s = %d; an unregistered method on a public path was served",
					m, path, rec.Code)
			}
		}
	}
}
