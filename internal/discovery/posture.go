package discovery

import (
	"sort"
	"strings"

	"api-gateway/internal/config"
)

// Posture classifications for a discovered endpoint.
const (
	PostureProtected   = "protected"   // all core controls active
	PosturePartial     = "partial"     // some core controls active
	PostureUnprotected = "unprotected" // no core controls active
	PostureShadow      = "shadow"      // observed but matches no configured route
)

// Controls describes the effective security controls applied to an endpoint,
// after merging global security settings with per-route overrides.
type Controls struct {
	AuthRequired bool `json:"auth_required"`
	WAF          bool `json:"waf"`
	RateLimit    bool `json:"rate_limit"`
	DLP          bool `json:"dlp"`
	BotProtect   bool `json:"bot_protection"`
	IPGuard      bool `json:"ip_guard"`
}

// PostureEngine resolves the effective controls and posture for any path using
// the current gateway configuration. It is rebuilt on config hot-reload.
type PostureEngine struct {
	cfg    config.GatewayConfig
	routes []config.RouteConfig // sorted longest-prefix first for matching
}

// NewPostureEngine builds an engine from the gateway configuration.
func NewPostureEngine(cfg config.GatewayConfig) *PostureEngine {
	routes := make([]config.RouteConfig, len(cfg.Routes))
	copy(routes, cfg.Routes)
	// Longest path first so the most specific route wins (mirrors ServeMux-ish
	// intent and makes posture deterministic).
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Path) > len(routes[j].Path)
	})
	return &PostureEngine{cfg: cfg, routes: routes}
}

// matchRoute returns the configured route that will actually SERVE the path, or
// nil.
//
// It mirrors http.ServeMux, because that is what the proxy routes with, and the
// two must agree about which route owns a request. They did not: this resolver
// matched every route as a prefix, while ServeMux treats a pattern WITHOUT a
// trailing slash as an exact match. So a route declared
//
//   - path: /public          # require_auth: false
//   - path: /                # require_auth: true
//
// handed its permissive posture to the whole "/public/..." subtree, which
// ServeMux actually routes to the catch-all. The gate in front of auth read this
// resolver, so "/public/admin/delete-everything" reached the backend with no
// authentication at all, while the posture dashboard reported it as belonging to
// the route the operator had deliberately opened. Confirmed end to end against a
// running gateway (2026-09-02) — which also disproves warnExactMatchRoutes's
// claim that this mismatch "fails closed".
//
// The rules, matching ServeMux exactly:
//   - a pattern ending in "/" owns its subtree;
//   - any other pattern matches that one path and nothing below it;
//   - the longest pattern wins (routes are pre-sorted).
//
// Matching is case-insensitive (both sides lowercased) for the same reason
// middleware/abuse.go's BFLA check already is: a backend that routes
// case-insensitively would otherwise let "/Admin" slip past an "/admin" route
// override and fall back to the weaker global posture.
func (e *PostureEngine) matchRoute(path string) *config.RouteConfig {
	lpath := strings.ToLower(path)
	for i := range e.routes {
		if routeServes(lpath, strings.ToLower(e.routes[i].Path)) {
			return &e.routes[i]
		}
	}
	return nil
}

// routeServes reports whether an http.ServeMux pattern of this shape would be
// selected for path. Both arguments are already lower-cased by the caller.
//
// A pattern may carry a leading "METHOD " and/or a host (see
// config.RoutePatterns); neither participates in this path-only resolution, so
// they are stripped first. Stripping the host rather than ignoring the route
// entirely is deliberate: the reporting side (catalog rows) knows only a path
// template, and reporting a host-scoped route's posture is better than reporting
// none.
func routeServes(path, pattern string) bool {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = pattern[i+1:] // drop "METHOD "
	}
	if i := strings.IndexByte(pattern, '/'); i > 0 {
		pattern = pattern[i:] // drop a leading host
	}
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "/") {
		// Subtree pattern: owns the prefix and everything under it. ServeMux also
		// serves the bare "/x" for a registered "/x/" (via a redirect), so treat
		// the slash-less form as owned too — the posture must not differ between
		// "/x" and "/x/".
		return config.PathHasPrefix(path, pattern) || path == strings.TrimSuffix(pattern, "/")
	}
	return path == pattern
}

// ControlsFor computes the effective controls for a request path. The second
// return value is false when no route matches (i.e. a shadow endpoint).
func (e *PostureEngine) ControlsFor(path string) (Controls, bool) {
	sec := e.cfg.Security
	route := e.matchRoute(path)

	c := Controls{
		WAF:        sec.WAF.Enabled,
		RateLimit:  sec.RateLimit.Enabled,
		DLP:        sec.DLP.Enabled,
		BotProtect: sec.Bot.Enabled,
		IPGuard:    sec.IPGuard.Enabled,
		// Auth is "required" only when globally enabled and the path is not excluded.
		AuthRequired: sec.Auth.Enabled && !e.authExcluded(path),
	}

	if route != nil {
		if route.RequireAuth != nil {
			c.AuthRequired = *route.RequireAuth
		}
		if route.WAF != nil {
			c.WAF = *route.WAF
		}
		if route.DLP != nil {
			c.DLP = *route.DLP
		}
		if route.RateLimit != nil {
			c.RateLimit = route.RateLimit.Enabled
		}
	}

	return c, route != nil
}

// RateLimitFor resolves the effective rate-limit config for a path. A per-route
// rate_limit override fully replaces the global config (its own requests/window/
// fail_closed). The returned routeKey isolates a route's counter from the global
// bucket so distinct routes don't share a window; it is empty when the global
// config applies. enabled reports whether limiting runs for the path at all.
func (e *PostureEngine) RateLimitFor(path string) (cfg config.RateLimitConfig, routeKey string, enabled bool) {
	route := e.matchRoute(path)
	if route != nil && route.RateLimit != nil {
		return *route.RateLimit, route.Path, route.RateLimit.Enabled
	}
	g := e.cfg.Security.RateLimit
	return g, "", g.Enabled
}

// authExcluded is case-insensitive for the same reason matchRoute is: an
// operator's exclude prefix must not be defeatable by a case-varied path.
func (e *PostureEngine) authExcluded(path string) bool {
	lpath := strings.ToLower(path)
	for _, ex := range e.cfg.Security.Auth.Exclude {
		if config.PathHasPrefix(lpath, strings.ToLower(ex)) {
			return true
		}
	}
	return false
}

// Classify returns the posture label for a path.
func (e *PostureEngine) Classify(path string) string {
	c, matched := e.ControlsFor(path)
	if !matched {
		return PostureShadow
	}
	return classifyControls(c)
}

// classifyControls maps the three core perimeter controls (auth, WAF, rate-limit)
// onto a posture label. DLP/bot/ip-guard are treated as supplementary and do not
// by themselves move an endpoint out of "unprotected".
func classifyControls(c Controls) string {
	core := 0
	if c.AuthRequired {
		core++
	}
	if c.WAF {
		core++
	}
	if c.RateLimit {
		core++
	}
	switch core {
	case 3:
		return PostureProtected
	case 0:
		return PostureUnprotected
	default:
		return PosturePartial
	}
}

// RiskScore computes a 0-100 risk score for an endpoint from its posture and
// observed traffic. Higher = more dangerous. The model rewards missing controls
// and amplifies risk when sensitive data (PII) or auth-less access is observed.
func RiskScore(path string, e *PostureEngine, stats EndpointStats) int {
	c, matched := e.ControlsFor(path)

	score := 0
	if !matched {
		score += 35 // shadow endpoints are inherently risky
	}
	if !c.AuthRequired {
		score += 25
	}
	if !c.WAF {
		score += 15
	}
	if !c.RateLimit {
		score += 10
	}
	if !c.DLP {
		score += 5
	}

	// Sensitive-data exposure sharply raises risk, especially without auth.
	if stats.PIICount > 0 {
		score += 10
		if !c.AuthRequired {
			score += 15
		}
	}
	// Anonymous traffic on an endpoint that should be authenticated.
	if c.AuthRequired && stats.AnonCount > 0 {
		score += 10
	}
	// High error ratio can indicate probing/abuse.
	if stats.RequestCount > 0 {
		errRatio := float64(stats.ErrorCount) / float64(stats.RequestCount)
		if errRatio > 0.5 {
			score += 10
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

// EndpointStats is the minimal traffic summary the risk model needs.
type EndpointStats struct {
	RequestCount int64
	ErrorCount   int64
	AnonCount    int64
	PIICount     int64
}
