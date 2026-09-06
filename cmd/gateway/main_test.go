package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"api-gateway/internal/api"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/gateway"
	"api-gateway/internal/license"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
)

// issueTestLicense sets up a throwaway Ed25519 keypair for the duration of
// the test (via license.SetPublicKeyForTesting), signs a valid never-expiring
// license, writes it to a temp file, and returns its path — for tests that
// need loadValidatedConfig to pass the (now hard-required) license gate
// without depending on a real release build's embedded key.
func issueTestLicense(t *testing.T) string {
	t.Helper()
	return issueTestLicenseWithClaims(t, license.Claims{Licensee: "test", Tier: "internal"})
}

// issueTestLicenseWithClaims is issueTestLicense's general form, for tests
// exercising tier/feature entitlement (RequiresObserve, CheckFeatureGates).
func issueTestLicenseWithClaims(t *testing.T, claims license.Claims) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate test license key: %v", err)
	}
	restore := license.SetPublicKeyForTesting(base64.StdEncoding.EncodeToString(pub))
	t.Cleanup(restore)

	if claims.Licensee == "" {
		claims.Licensee = "test"
	}
	signed, err := license.Sign(priv, claims)
	if err != nil {
		t.Fatalf("sign test license: %v", err)
	}
	path := filepath.Join(t.TempDir(), "test.lic")
	if err := os.WriteFile(path, []byte(signed), 0o600); err != nil {
		t.Fatalf("write test license: %v", err)
	}
	return path
}

// TestChain_IdentifiesCallerOnRoutesThatDoNotRequireAuth is the regression test
// for a finding that mattered commercially rather than technically.
//
// JWT auth used to be gated OFF entirely on routes whose effective controls did
// not require it. Nothing then looked at the Authorization header there, so a
// caller presenting a perfectly valid token was recorded as anonymous. The
// catalog's anon_count therefore meant "not checked", while the findings layer
// read it as "no credential present" and reported PII on such a route as
// "N requests arrived without authentication" — a claim the customer can
// disprove from their own access logs, which is the fastest way to lose their
// trust in every other number in the report. It also left
// sensitive_data_auth_not_required unreachable in production, since that
// finding needs anon_count == 0 on a route that does not require auth.
//
// The chain now runs an identify-only pass on such routes: identity is
// extracted, nothing is ever rejected.
func TestChain_IdentifiesCallerOnRoutesThatDoNotRequireAuth(t *testing.T) {
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

	// The backend reports back what identity the gateway propagated to it.
	var gotSubject string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubject = r.Header.Get("X-Gateway-Subject")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	const secret = "chain-identify-test-secret-32-chars!!"
	noAuth := false
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			// Auth is configured and globally on, but this route opts out of
			// requiring it — the shape that produced the bug.
			Auth: config.AuthConfig{Enabled: true, Secret: secret},
		},
		Routes: []config.RouteConfig{
			{Path: "/open", Upstreams: []string{bu.String()}, RequireAuth: &noAuth},
		},
	}

	log := logger.New("error")
	handler, _, err := gateway.BuildHandlerChain(cfg, log, st, nil, discovery.NewPostureEngine(cfg), nil)
	if err != nil {
		t.Fatalf("BuildHandlerChain: %v", err)
	}

	token := signHS256(t, secret, "partner@example.com")

	// 1. A valid token on a route that does not require auth must still be read.
	r := httptest.NewRequest(http.MethodGet, "/open", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.RemoteAddr = "1.2.3.4:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an identify-only pass must never reject", rec.Code)
	}
	if gotSubject != "partner@example.com" {
		t.Fatalf("propagated subject = %q, want partner@example.com — the caller was "+
			"authenticated and must not be recorded as anonymous", gotSubject)
	}

	// 2. The same route must still serve callers with no token at all, and with
	//    a broken one: identify-only means identify, never enforce.
	for name, hdr := range map[string]string{"no token": "", "garbage token": "Bearer not.a.jwt"} {
		gotSubject = "sentinel"
		r2 := httptest.NewRequest(http.MethodGet, "/open", nil)
		if hdr != "" {
			r2.Header.Set("Authorization", hdr)
		}
		r2.RemoteAddr = "1.2.3.4:1"
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, r2)
		if rec2.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", name, rec2.Code)
		}
		if gotSubject != "" {
			t.Fatalf("%s: propagated subject = %q, want empty", name, gotSubject)
		}
	}
}

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
	handler, _, err := gateway.BuildHandlerChain(cfg, log, st, nil, postureEng, nil)
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
	licPath := issueTestLicense(t)
	body := `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
trusted_proxies: ["10.0.0.0/8"]
license_path: "` + licPath + `"
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, nets, _, _, err := loadValidatedConfig(p)
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

// TestRunLicenseRecheck_UpdatesStatusIndependentlyOfConfigReload is a
// regression test for the licensing "continuous enforcement" gap (audit
// finding, 2026-08-23): watchConfigFile only re-validates the license as a
// side effect of a gateway.yaml edit, so a long-lived process whose config
// is never touched again — the steady-state case — would keep serving on a
// stale license status (and, worse, an actually-expired license) forever.
// runLicenseRecheck is licenseRecheckLoop's per-tick body; this proves it
// updates the Server's published license status on its own, without any
// config file ever changing.
func TestRunLicenseRecheck_UpdatesStatusIndependentlyOfConfigReload(t *testing.T) {
	adminSrv := api.NewServer(nil, logger.New("error"), config.GatewayConfig{}, nil, nil, nil, nil, nil, nil, nil)

	var currentLicensePath atomic.Value
	currentLicensePath.Store("") // nothing configured yet -> reports invalid

	getLicenseValid := func() any {
		rec := httptest.NewRecorder()
		adminSrv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/license", nil))
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal /api/license body: %v", err)
		}
		return body["valid"]
	}

	runLicenseRecheck(&currentLicensePath, logger.New("error"), adminSrv)
	if got := getLicenseValid(); got != false {
		t.Fatalf("before a license is configured: /api/license valid = %v, want false", got)
	}

	// Point at a real, valid license and re-run the check — the published
	// status must update WITHOUT any config-file hot-reload happening at all.
	currentLicensePath.Store(issueTestLicense(t))
	runLicenseRecheck(&currentLicensePath, logger.New("error"), adminSrv)
	if got := getLicenseValid(); got != true {
		t.Fatalf("after runLicenseRecheck picked up a newly-valid license: /api/license valid = %v, want true", got)
	}
}

// TestLoadValidatedConfig_NoLicenseFailsBoot is the licensing enforcement
// boundary: a deployment with no valid license_path (the default — nothing
// baked into a plain `go build`, nothing configured) must not come up at all,
// on boot or on hot-reload — same treatment as any other config.Validate
// rejection. A soft degrade (e.g. forcing Observe mode) would still give away
// the discovery/posture/findings value for free, which defeats licensing
// entirely.
func TestLoadValidatedConfig_NoLicenseFailsBoot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gateway.yaml")
	body := `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
observe: false
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, _, licStatus, _, err := loadValidatedConfig(p)
	if err == nil {
		t.Fatal("expected loadValidatedConfig to reject a config with no valid license")
	}
	if licStatus.Valid {
		t.Fatal("expected no license to be configured in this test env")
	}
}

// TestLoadValidatedConfig_TrialTierForcesObserveEvenWithObserveFalse is the
// tier-entitlement boundary: a "trial" license may not enforce, full stop —
// the operator's own `observe: false` must not override it.
func TestLoadValidatedConfig_TrialTierForcesObserveEvenWithObserveFalse(t *testing.T) {
	licPath := issueTestLicenseWithClaims(t, license.Claims{Tier: "trial"})
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	body := `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
observe: false
license_path: "` + licPath + `"
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, _, _, _, err := loadValidatedConfig(p)
	if err != nil {
		t.Fatalf("loadValidatedConfig: %v", err)
	}
	if !cfg.Observe {
		t.Fatal("a trial-tier license must force Observe=true regardless of observe: false in config")
	}
}

// TestLoadValidatedConfig_ProductionTierRespectsConfig is the counterpart:
// a production-tier license must NOT force Observe — the operator's config
// decides.
func TestLoadValidatedConfig_ProductionTierRespectsConfig(t *testing.T) {
	licPath := issueTestLicenseWithClaims(t, license.Claims{Tier: "production"})
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	body := `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
observe: false
license_path: "` + licPath + `"
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, _, _, _, err := loadValidatedConfig(p)
	if err != nil {
		t.Fatalf("loadValidatedConfig: %v", err)
	}
	if cfg.Observe {
		t.Fatal("a production-tier license must not force Observe when the operator set observe: false")
	}
}

// TestLoadValidatedConfig_UnentitledMultitenancyFailsBoot is the feature-
// entitlement boundary: a license without the "multitenancy" feature must
// not let a config enabling it boot.
func TestLoadValidatedConfig_UnentitledMultitenancyFailsBoot(t *testing.T) {
	licPath := issueTestLicenseWithClaims(t, license.Claims{Tier: "production", Features: []string{"sso"}}) // no "multitenancy"
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	body := `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
license_path: "` + licPath + `"
multitenancy:
  enabled: true
  tenants:
    - id: acme
      hosts: ["acme.example.com"]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, _, _, err := loadValidatedConfig(p); err == nil {
		t.Fatal("expected boot to fail: multitenancy enabled but not licensed")
	}
}

// TestLoadValidatedConfig_UnrestrictedLicenseAllowsMultitenancy confirms the
// backward-compatible default: a license with no Features set at all (every
// license issued before feature-gating existed) must not suddenly break an
// existing multitenancy deployment.
func TestLoadValidatedConfig_UnrestrictedLicenseAllowsMultitenancy(t *testing.T) {
	licPath := issueTestLicenseWithClaims(t, license.Claims{Tier: "production"}) // Features: nil
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	body := `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis: {password: "redis-pass"}
license_path: "` + licPath + `"
multitenancy:
  enabled: true
  tenants:
    - id: acme
      hosts: ["acme.example.com"]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, _, _, err := loadValidatedConfig(p); err != nil {
		t.Fatalf("an unrestricted (no Features) license must not block multitenancy: %v", err)
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

	licPath := issueTestLicense(t)
	good := write("good.yaml", `
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
redis:
  password: "redis-pass"
trusted_proxies: ["10.0.0.0/8"]
license_path: "`+licPath+`"
`)
	if _, _, _, _, err := loadValidatedConfig(good); err != nil {
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
		if _, _, _, _, err := loadValidatedConfig(p); err == nil {
			t.Fatalf("%s: unsafe config accepted", name)
		}
	}
}

// signHS256 mints a short-lived HS256 token. The gateway requires an exp claim
// (a signed token with no expiry would otherwise live forever), so one is set.
func signHS256(t *testing.T, secret, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}
