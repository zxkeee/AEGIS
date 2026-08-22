// Package gateway assembles the data-plane middleware chain. It is extracted
// from cmd/gateway/main.go (audit finding F5) so the chain — whose ordering is
// load-bearing — can be unit-tested directly (see chain_test.go), and so main.go
// is left with only process wiring and lifecycle.
package gateway

import (
	"context"
	"net/http"
	"os"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/proxy"
)

// step is one named entry in the data-plane chain. Naming each step makes the
// order explicit data that chain_test.go can pin, so an accidental reordering
// fails CI instead of shipping.
type step struct {
	name string
	mw   middleware.Middleware
}

// chainSteps returns the ordered, named middleware steps wrapping the proxy.
// The first element is the OUTERMOST middleware. Order is deliberate:
//
//   - TenantResolve must run first (everything downstream reads the tenant).
//   - CleanHeaders strips spoofed identity/forwarding headers before anything
//     trusts them.
//   - Discovery sits inside WAF/rate-limit/bot (so attacks stay out of the
//     catalog) but outside auth/DLP (so it sees identity + PII and the final
//     status).
//   - AbuseDetection runs AFTER auth so it sees verified JWT roles.
//
// Read this before reordering anything.
func chainSteps(cfg config.GatewayConfig, log *logger.Logger, st middleware.Store, cat middleware.Catalog, postureEng *discovery.PostureEngine, schemaSpecFor func(context.Context) *discovery.Spec) []step {
	// effective resolves the merged controls (global security.* + per-route
	// overrides) for a request path. The route-overridable controls below are
	// built force-enabled and gated on these booleans, so a route can switch a
	// control on even when it is globally off (and vice versa).
	effective := func(path string) discovery.Controls {
		c, _ := postureEng.ControlsFor(path)
		return c
	}

	// authMW: enforce JWT when the effective controls require auth for the path.
	// Built once with auth force-enabled (so JWKS init etc. run) only when auth is
	// reachable — globally on, or switched on by at least one route override.
	authMW := middleware.Middleware(passthroughMW)
	if cfg.Security.Auth.Enabled || anyRouteRequiresAuth(cfg.Routes) {
		authCfg := cfg.Security.Auth
		authCfg.Enabled = true
		forced := middleware.NewJWTAuth(authCfg, log, st).Middleware()
		authMW = middleware.RouteGate(func(p string) bool { return effective(p).AuthRequired }, forced)
	}

	// wafMW / dlpMW / rateMW: same pattern for the other route-overridable controls.
	wafMW := middleware.Middleware(passthroughMW)
	if cfg.Security.WAF.Enabled || anyRouteEnablesBool(cfg.Routes, func(r config.RouteConfig) *bool { return r.WAF }) {
		wafCfg := cfg.Security.WAF
		wafCfg.Enabled = true
		wafMW = middleware.RouteGate(func(p string) bool { return effective(p).WAF }, middleware.WAF(wafCfg, log, st))
	}

	dlpMW := middleware.Middleware(passthroughMW)
	if cfg.Security.DLP.Enabled || anyRouteEnablesBool(cfg.Routes, func(r config.RouteConfig) *bool { return r.DLP }) {
		dlpCfg := cfg.Security.DLP
		dlpCfg.Enabled = true
		dlpMW = middleware.RouteGate(func(p string) bool { return effective(p).DLP }, middleware.DLP(dlpCfg, log, st))
	}

	// rateMW resolves the effective rate-limit config per request path, so a route
	// override controls both on/off AND its own requests/window. Counter keys are
	// scoped ("gw" + route) so they never collide with the admin-plane limiter.
	rateMW := middleware.Middleware(passthroughMW)
	if cfg.Security.RateLimit.Enabled || anyRouteEnablesRateLimit(cfg.Routes) {
		rateMW = middleware.RouteRateLimit(postureEng.RateLimitFor, log, st)
	}

	return []step{
		{"TenantResolve", middleware.TenantResolve(cfg.Multitenancy, cfg.Routes, log, st)}, // P0-3: resolve tenant first
		{"CleanHeaders", middleware.CleanHeaders()},                                        // SEC: strip spoofed X-Gateway-* / X-JA3 headers
		{"UpstreamFingerprint", middleware.UpstreamFingerprint(cfg.Security.Bot)},          // trust upstream (Cloudflare) JA3 from trusted proxies
		{"TLSFingerprint", middleware.TLSFingerprint()},                                    // SEC (P0-4): inject real ClientHello fingerprint
		{"SecurityHeaders", middleware.SecurityHeaders()},                                  // ARCH-6: security headers on every response
		{"RequestID", middleware.RequestID()},                                              // ARCH-4: request ID for log correlation
		{"PathSanity", middleware.PathSanity(log, st)},                                     // SEC: reject traversal/encoded-separator paths before any prefix policy
		{"CORS", middleware.CORS(cfg.Security.CORS)},
		{"IPGuard", middleware.IPGuard(cfg.Security.IPGuard, log, st)},
		{"ThreatFeed", middleware.ThreatFeed(cfg.Security.ThreatFeed, log, st)},
		{"RateLimit", rateMW},
		{"BotProtection", middleware.BotProtection(cfg.Security.Bot, log, st)},
		{"Challenge", middleware.Challenge(cfg.Security.Challenge, log, st)},
		{"WAF", wafMW},
		{"Discovery", middleware.Discovery(cfg.Security.Inventory, cat, log)}, // passive API discovery
		{"Auth", authMW},
		{"SchemaValidation", middleware.SchemaValidation(cfg.Security.Schema, schemaSpecFor, log, st)}, // positive security: validate against OpenAPI contract
		{"AbuseDetection", middleware.AbuseDetection(cfg.Security.Abuse, log, st)},                     // BOLA/BFLA (needs verified roles)
		{"DLP", dlpMW},
		{"BehaviorAnalysis", middleware.BehaviorAnalysis(cfg.Security.Behavior, log, st)},
	}
}

// BuildHandlerChain constructs the full data-plane handler: the security
// middleware chain wrapping the reverse proxy. The returned *proxy.Gateway is the
// innermost handler (exposed for health/metrics wiring).
//
// postureEng is the authority for *effective* per-route controls (global
// security.* merged with per-route overrides). The auth/WAF/DLP/rate-limit
// controls are wrapped in middleware.RouteGate so a per-route override is
// actually enforced in the data plane — not merely reported by the posture
// dashboard.
func BuildHandlerChain(cfg config.GatewayConfig, log *logger.Logger, st middleware.Store, catalog *discovery.Catalog, postureEng *discovery.PostureEngine) (http.Handler, *proxy.Gateway, error) {
	gw, err := proxy.New(cfg.Routes, log)
	if err != nil {
		return nil, nil, err
	}

	// A nil *discovery.Catalog must be passed as a nil interface so the Discovery
	// middleware's nil-check works (a typed-nil pointer in an interface is non-nil).
	var cat middleware.Catalog
	if catalog != nil {
		cat = catalog
	}

	// Schema enforcement's spec resolver: per-tenant-aware (a tenant's own
	// PUT /api/discovery/spec upload takes precedence over the config
	// fallback, via SpecForEnforcement's bounded-staleness cache) when a
	// catalog is wired — Postgres is what actually stores per-tenant
	// uploaded specs. Without a catalog (Postgres/discovery disabled), falls
	// back to a fixed closure over the config-level spec only, matching the
	// pre-fix single-spec behavior for that degraded mode. (Audit finding,
	// 2026-08-22 — see SpecForEnforcement's doc comment for the full story.)
	var schemaSpecFor func(context.Context) *discovery.Spec
	if catalog != nil {
		schemaSpecFor = catalog.SpecForEnforcement
	} else {
		spec := enforcementSpec(cfg, log)
		schemaSpecFor = func(context.Context) *discovery.Spec { return spec }
	}

	steps := chainSteps(cfg, log, st, cat, postureEng, schemaSpecFor)
	mws := make([]middleware.Middleware, len(steps))
	for i, s := range steps {
		mws[i] = s.mw
	}
	return middleware.Chain(gw, mws...), gw, nil
}

// enforcementSpec parses the config-level OpenAPI/Swagger document
// (discovery.spec_path) used by schema enforcement. It returns nil — disabling
// enforcement, fail-open — when enforcement is off, no path is set, or the
// document cannot be read/parsed (logged, never fatal). Re-read on every chain
// build so a hot-reload picks up an edited spec.
func enforcementSpec(cfg config.GatewayConfig, log *logger.Logger) *discovery.Spec {
	if !cfg.Security.Schema.Enabled {
		return nil
	}
	path := cfg.Discovery.SpecPath
	if path == "" {
		log.Warn("schema enforcement enabled but discovery.spec_path is empty — nothing to enforce", nil)
		return nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path, not user input
	if err != nil {
		log.Error("schema enforcement: spec read failed (enforcement disabled)", map[string]any{"error": err.Error(), "path": path})
		return nil
	}
	spec, err := discovery.ParseSpec(raw)
	if err != nil {
		log.Error("schema enforcement: spec parse failed (enforcement disabled)", map[string]any{"error": err.Error(), "path": path})
		return nil
	}
	log.Info("schema enforcement enabled", map[string]any{
		"path": path, "operations": spec.OpCount(), "block_mode": cfg.Security.Schema.BlockMode,
	})
	return spec
}

// passthroughMW is a no-op middleware used when a control is fully inactive
// (globally off and not enabled by any route override), so the gate machinery is
// skipped entirely and no engine (e.g. Coraza) is constructed.
func passthroughMW(next http.Handler) http.Handler { return next }

// anyRouteRequiresAuth reports whether any route explicitly turns auth on.
func anyRouteRequiresAuth(routes []config.RouteConfig) bool {
	for _, r := range routes {
		if r.RequireAuth != nil && *r.RequireAuth {
			return true
		}
	}
	return false
}

// anyRouteEnablesBool reports whether any route sets the selected *bool override
// to true (used for WAF/DLP).
func anyRouteEnablesBool(routes []config.RouteConfig, sel func(config.RouteConfig) *bool) bool {
	for _, r := range routes {
		if b := sel(r); b != nil && *b {
			return true
		}
	}
	return false
}

// anyRouteEnablesRateLimit reports whether any route turns rate limiting on.
func anyRouteEnablesRateLimit(routes []config.RouteConfig) bool {
	for _, r := range routes {
		if r.RateLimit != nil && r.RateLimit.Enabled {
			return true
		}
	}
	return false
}
