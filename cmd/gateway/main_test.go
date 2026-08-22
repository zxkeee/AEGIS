package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/gateway"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// TestChain_PostureMatchesEnforcement is the guard against the headline bug class:
// the posture engine must never report protection the data plane does not deliver.
// It builds the real handler chain and asserts, for representative routes, that the
// posture label and the chain's actual behaviour agree.
func TestChain_PostureMatchesEnforcement(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	st, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := middleware.InitTrustedProxies(nil); err != nil {
		t.Fatalf("InitTrustedProxies: %v", err)
	}

	// A backend that records whether it was actually reached.
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	requireAuth := true
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Enabled: false}, // auth globally OFF
		},
		Routes: []config.RouteConfig{
			// Protected purely via per-route override (the exact scenario that
			// previously reported "protected" while reaching the backend open).
			{Path: "/secure", Upstreams: []string{bu.String()}, RequireAuth: &requireAuth},
			// No override: inherits the (off) global posture.
			{Path: "/open", Upstreams: []string{bu.String()}},
		},
	}

	log := logger.New("error")
	postureEng := discovery.NewPostureEngine(cfg)
	handler, _, err := gateway.BuildHandlerChain(cfg, log, st, nil, postureEng)
	if err != nil {
		t.Fatalf("BuildHandlerChain: %v", err)
	}

	// /secure: posture reports auth as required (here "partial" — only auth is on)
	// -> the chain MUST reject an unauthenticated request before the backend.
	if c, _ := postureEng.ControlsFor("/secure"); !c.AuthRequired {
		t.Fatal("/secure posture: AuthRequired should be true via per-route override")
	}
	if label := postureEng.Classify("/secure"); label == discovery.PostureUnprotected || label == discovery.PostureShadow {
		t.Fatalf("/secure posture: got %q, want a protected/partial label", label)
	}
	reached = false
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secure", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/secure: posture is protected but chain returned %d (want 401)", rec.Code)
	}
	if reached {
		t.Fatal("/secure: backend reached without auth — posture lied about protection")
	}

	// /open: no auth control -> request passes through to the backend.
	reached = false
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/open", nil))
	if !reached {
		t.Fatalf("/open: expected passthrough to backend, got status %d", rec.Code)
	}
}

// TestLoadValidatedConfig_DoesNotCommitTrustedProxies is a regression test:
// loadValidatedConfig used to call middleware.InitTrustedProxies directly,
// committing the parsed trusted_proxies to the global RealIP trust boundary
// immediately — before the rest of a hot-reload (BuildHandlerChain) was known
// to succeed. A reload that failed later left that new trust boundary live
// under the OLD, still-serving handler chain, contradicting "previous config
// stays active." loadValidatedConfig must now only PARSE and return the
// trusted-proxy set; the caller commits via middleware.SetTrustedProxies only
// once the entire reload has succeeded (see reload() in main.go).
func TestLoadValidatedConfig_DoesNotCommitTrustedProxies(t *testing.T) {
	middleware.SetTrustedProxies(nil) // baseline: no trusted proxies configured
	t.Cleanup(func() { middleware.SetTrustedProxies(nil) })

	dir := t.TempDir()
	p := filepath.Join(dir, "trusted.yaml")
	body := `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
trusted_proxies: ["10.0.0.0/8"]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, nets, err := loadValidatedConfig(p)
	if err != nil {
		t.Fatalf("loadValidatedConfig: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("parsed nets = %v, want 1 entry (10.0.0.0/8)", nets)
	}

	// The proxy at 10.0.0.1 must NOT be trusted yet — loadValidatedConfig only
	// parsed the new set, it never committed it.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := middleware.RealIP(r); got != "10.0.0.1" {
		t.Fatalf("RealIP before commit = %q, want %q (10.0.0.0/8 must not be trusted until SetTrustedProxies is called)", got, "10.0.0.1")
	}

	// Only after the caller explicitly commits (mirroring reload() committing
	// after BuildHandlerChain succeeds) does the new trust boundary apply.
	middleware.SetTrustedProxies(nets)
	if got := middleware.RealIP(r); got != "203.0.113.9" {
		t.Fatalf("RealIP after commit = %q, want %q (10.0.0.0/8 should now be trusted)", got, "203.0.113.9")
	}
}

// loadValidatedConfig is the shared gate for startup AND hot-reload: a config
// that fails Validate must be rejected in both paths (hot-reload used to skip
// validation entirely, letting an unsafe edit go live).
func TestLoadValidatedConfig_RejectsUnsafeConfig(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	good := write("good.yaml", `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis:
  password: "redis-pass"
trusted_proxies: ["10.0.0.0/8"]
`)
	if _, _, err := loadValidatedConfig(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]string{
		"placeholder admin secret": `
admin_auth: true
admin_secret: "changeme"
redis: {password: "redis-pass"}
`,
		"invalid trusted_proxies": `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
trusted_proxies: ["not-an-ip"]
`,
		"unsupported load_balance": `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
routes:
  - path: "/x"
    upstreams: ["http://b:1"]
    load_balance: "least_conn"
`,
	}
	for name, body := range cases {
		p := write(strings.ReplaceAll(name, " ", "-")+".yaml", body)
		if _, _, err := loadValidatedConfig(p); err == nil {
			t.Fatalf("%s: unsafe config accepted", name)
		}
	}
}
