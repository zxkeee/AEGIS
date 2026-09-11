package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
)

// The console shell is served with a strict script-src ('self', no inline, no
// eval) so injected script cannot execute; style-src is relaxed to
// 'unsafe-inline' for the animation layer (documented tradeoff — style
// injection cannot run code).
func TestConsole_ShellCSP(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	rec := httptest.NewRecorder()
	h.serveDashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("shell status = %d, want 200", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("script-src not strict 'self': %q", csp)
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("script-src must not allow unsafe-inline/eval: %q", csp)
	}
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q", want)
		}
	}
	if !strings.Contains(rec.Body.String(), `<div id="root">`) {
		t.Fatalf("shell did not serve the SPA root element")
	}
}

// The console is served under one constant URL (vite.config.ts pins
// assets/console.js), so a long immutable cache would leave an upgraded gateway
// serving the previous console out of the browser cache with no request that
// could discover the new one — a fixed console that never reaches the operator.
// The previous version of this test asserted the immutable header, pinning that
// behaviour as intended.
func TestConsole_AssetServing(t *testing.T) {
	h := &handlers{log: logger.New("error")}

	rec := httptest.NewRecorder()
	h.serveConsoleAsset(rec, httptest.NewRequest(http.MethodGet, "/assets/console.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("asset status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Fatalf("asset content-type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Fatalf("asset is cached immutably under a constant URL: %q", cc)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag; without a validator every load re-downloads the bundle")
	}

	t.Run("a matching validator revalidates", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/console.js", nil)
		req.Header.Set("If-None-Match", etag)
		rec := httptest.NewRecorder()
		h.serveConsoleAsset(rec, req)
		if rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", rec.Code)
		}
	})

	t.Run("a stale validator gets the new bundle", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/console.js", nil)
		req.Header.Set("If-None-Match", `"0000000000000000"`)
		rec := httptest.NewRecorder()
		h.serveConsoleAsset(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 — a stale cache was never refreshed", rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatal("304 body semantics on a 200 response")
		}
	})

	rec404 := httptest.NewRecorder()
	h.serveConsoleAsset(rec404, httptest.NewRequest(http.MethodGet, "/assets/nope.js", nil))
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("unknown asset = %d, want 404", rec404.Code)
	}
}

func TestConsole_Env(t *testing.T) {
	h := &handlers{log: logger.New("error"), cfg: config.GatewayConfig{AdminAuth: true}}
	rec, body := callGet(h.consoleEnv, "/api/console/env", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("env status = %d", rec.Code)
	}
	if body["admin_auth"] != true {
		t.Fatalf("env admin_auth = %v, want true", body["admin_auth"])
	}
	if _, ok := body["sso"]; !ok {
		t.Fatal("env missing sso flag")
	}
}
