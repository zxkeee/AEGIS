// Package gateway assembles the data-plane middleware chain. It is extracted
// from cmd/gateway/main.go (audit finding F5) so the chain — whose ordering is
// load-bearing — can be unit-tested directly (see chain_test.go), and so main.go
// is left with only process wiring and lifecycle.
package gateway

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"api-gateway/internal/audit"

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

	// authMW: enforce JWT when the effective controls require auth for the path,
	// and IDENTIFY (never reject) when they do not. Built once with auth
	// force-enabled (so JWKS init etc. run) only when auth is reachable —
	// globally on, or switched on by at least one route override.
	//
	// The soft branch matters beyond convenience. Skipping JWT entirely on
	// routes that do not require it meant nothing ever looked at the token, so a
	// caller presenting a perfectly valid one was recorded as anonymous. The
	// catalog's anon_count then meant "not checked" while the findings layer
	// read it as "no credential present" and reported PII on such a route as
	// "N requests arrived without authentication" — a claim a customer can
	// disprove from their own logs in a minute. It also made
	// sensitive_data_auth_not_required (the latent, warning-severity variant)
	// unreachable, since its condition is anon_count == 0 on a route that does
	// not require auth. Identifying without enforcing fixes all three.
	authMW := middleware.Middleware(passthroughMW)
	if cfg.Security.Auth.Enabled || anyRouteRequiresAuth(cfg.Routes) {
		authCfg := cfg.Security.Auth
		authCfg.Enabled = true
		enforcing := middleware.NewJWTAuth(authCfg, log, st).Middleware()

		// Same config, Observe on: extracts and propagates identity from a valid
		// token and passes everything else straight through, never returning 401.
		softCfg := authCfg
		softCfg.Observe = true
		identifyOnly := middleware.NewJWTAuth(softCfg, log, st).Middleware()

		authMW = middleware.RouteSwitch(
			func(p string) bool { return effective(p).AuthRequired },
			enforcing, identifyOnly)
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
		// Commercial RPS ceiling: near-outermost so an over-cap request costs the
		// least, but deliberately AFTER CleanHeaders — its deny path calls RealIP(),
		// and no control should read a client-supplied forwarding header before
		// CleanHeaders has sanitized the family. (Harmless today, since RealIP only
		// trusts XFF from a trusted_proxies peer either way, but this keeps the
		// "nothing reads identity headers before CleanHeaders" invariant total
		// rather than "total except one licensing control".)
		{"LicenseRateLimit", middleware.LicenseRateLimit(cfg.LicenseMaxRPS, log, st)},
		{"UpstreamFingerprint", middleware.UpstreamFingerprint(cfg.Security.Bot)}, // trust upstream (Cloudflare) JA3 from trusted proxies
		{"TLSFingerprint", middleware.TLSFingerprint()},                           // SEC (P0-4): inject real ClientHello fingerprint
		{"SecurityHeaders", middleware.SecurityHeaders()},                         // ARCH-6: security headers on every response
		{"RequestID", middleware.RequestID()},                                     // ARCH-4: request ID for log correlation
		{"PathSanity", middleware.PathSanity(log, st)},                            // SEC: reject traversal/encoded-separator paths before any prefix policy
		{"CORS", middleware.CORS(cfg.Security.CORS)},
		{"IPGuard", middleware.IPGuard(cfg.Security.IPGuard, log, st)},
		{"ThreatFeed", middleware.ThreatFeed(cfg.Security.ThreatFeed, log, st)},
		{"RateLimit", rateMW},
		{"BotProtection", middleware.BotProtection(cfg.Security.Bot, log, st)},
		{"Challenge", middleware.Challenge(cfg.Security.Challenge, log, st)},
		{"WAF", wafMW},
		{"Discovery", middleware.Discovery(cfg.Security.Inventory, cat, log)}, // passive API discovery
		{"Auth", authMW},
		// Immediately after Auth so a verified JWT subject always wins, and
		// before AbuseDetection, whose whole question is "did THIS consumer read
		// an object it does not own" — with opaque credentials and no pseudonym,
		// every caller is the same "ip:" consumer and that question has no
		// meaning. Inside Discovery, so the observation it is about to record
		// carries the identity.
		{"ConsumerID", middleware.ConsumerID(cfg.Security.ConsumerID, cfg.Security.ConsumerID.Salt)},
		{"SchemaValidation", middleware.SchemaValidation(cfg.Security.Schema, schemaSpecFor, log, st)},                 // positive security: validate against OpenAPI contract
		{"AbuseDetection", middleware.AbuseDetection(cfg.Security.Abuse, cfg.Security.Inventory.GraphQLPath, log, st)}, // BOLA/BFLA (needs verified roles)
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
	gw, err := proxy.New(cfg.Routes, cfg.Multitenancy, log)
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

	warnExactMatchRoutes(cfg.Routes, log)

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

// exactMatchRoutes returns routes that are almost certainly meant as subtrees
// but are declared without a trailing slash.
//
// The two halves of AEGIS disagree about what a route path means. The proxy is
// built on net/http's ServeMux, where a pattern WITHOUT a trailing slash matches
// that path EXACTLY and a pattern WITH one matches the subtree. The posture
// engine matches by segment prefix either way. So `/api/v1/customers` makes the
// dashboard claim the item paths under it are covered, while every request to
// `/api/v1/customers/7` gets a 404 from the proxy and never reaches the backend
// at all.
//
// The heuristic stays quiet where the exact match is obviously intended: a
// single-segment path (`/health`, `/metrics`) and any route whose subtree form
// is also declared, which means the operator already knows the distinction.
func exactMatchRoutes(routes []config.RouteConfig) []string {
	declared := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		declared[r.Path] = struct{}{}
	}

	var suspect []string
	for _, r := range routes {
		if strings.HasSuffix(r.Path, "/") {
			continue
		}
		if _, ok := declared[r.Path+"/"]; ok {
			continue
		}
		if strings.Count(strings.Trim(r.Path, "/"), "/") == 0 {
			continue
		}
		suspect = append(suspect, r.Path)
	}
	return suspect
}

// warnExactMatchRoutes logs the exactMatchRoutes finding once per chain build.
// It warns rather than refusing to start because the risk is a confusing 404,
// not a silent exposure: sub-paths fall through to whichever route really serves
// them, and that route's own posture applies.
//
// That last clause was NOT true when this comment was first written. The posture
// engine matched routes by prefix while ServeMux matches a slash-less pattern
// exactly, so the sub-paths kept the declared route's (often more permissive)
// controls while being served by a different route — a confirmed authentication
// bypass, the opposite of failing closed. discovery.matchRoute now mirrors
// ServeMux (see its doc comment), which is what makes the claim above hold.
// If that ever diverges again, this warning becomes a lie a second time.
//
// It cost real debugging time twice while building the sample stand, so it is
// worth one startup line.
func warnExactMatchRoutes(routes []config.RouteConfig, log *logger.Logger) {
	suspect := exactMatchRoutes(routes)
	if len(suspect) == 0 {
		return
	}
	log.Warn("routes declared without a trailing slash match that exact path only — sub-paths will 404", map[string]any{
		"routes": suspect,
		"hint":   "declare both forms (e.g. \"/api/v1/orders\" and \"/api/v1/orders/\") to serve a collection and its items",
	})
}

// probePaths are the liveness/readiness endpoints. They are unauthenticated by
// design and are polled by infrastructure that must never be told "slow down".
var probePaths = map[string]bool{"/health": true, "/readyz": true}

// BuildAdminChain assembles the control-plane handler: the admin API wrapped in
// its middleware. Extracted from main.go for the same reason BuildHandlerChain
// was — the ordering is load-bearing and needs a test that can see it.
//
// The per-IP rate limit sits OUTSIDE AdminAuth on purpose: AdminAuth returns
// early on a bad credential, so a limiter inside it would never see the
// unauthenticated brute-force traffic it exists to absorb.
//
// But it must not cover the probes. It is keyed by RealIP, and with
// trusted_proxies unset — the documented safe default — every request arriving
// through a load balancer collapses onto that balancer's address and shares one
// bucket. Any unauthenticated caller sending a handful of requests per second
// could therefore push /readyz over the limit, the balancer would see 429, mark
// the instance unhealthy and pull it from rotation: a full outage triggered from
// outside, with no credential. Probes are gated out of the limiter here, and
// their cost is bounded instead by caching the readiness check (see
// handlers.readyz), so exempting them cannot turn /readyz into a Redis
// amplifier.
func BuildAdminChain(adminSrv http.Handler, cfg config.GatewayConfig, log *logger.Logger, st middleware.Store, aud audit.Recorder) http.Handler {
	// 5 requests/second/IP, a fixed window enforced atomically in internal/store.
	// There is no separate burst allowance above this rate.
	adminRateLimit := config.RateLimitConfig{Enabled: true, Requests: 5, Window: time.Second}

	// The admin plane gets its own CORS policy when admin_cors is set; otherwise
	// it inherits security.cors (legacy behaviour). The console is same-origin,
	// so most deployments never need to set either for the admin plane.
	adminCORS := cfg.Security.CORS
	if cfg.AdminCORS != nil {
		adminCORS = *cfg.AdminCORS
	}

	rateLimited := middleware.RouteGate(
		func(p string) bool { return !probePaths[p] },
		middleware.RateLimit(adminRateLimit, "admin", log, st),
	)

	return middleware.Chain(adminSrv,
		middleware.RequestID(),       // outermost: stamp every request before anything else
		middleware.SecurityHeaders(), // must wrap AdminAuth so 401/403 responses carry CSP/HSTS
		rateLimited,
		middleware.AdminAuth(cfg, log, st, aud),
		middleware.CORS(adminCORS),
	)
}
