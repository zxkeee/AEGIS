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

// matchRoute returns the most specific configured route for a path, or nil.
func (e *PostureEngine) matchRoute(path string) *config.RouteConfig {
	for i := range e.routes {
		if strings.HasPrefix(path, e.routes[i].Path) {
			return &e.routes[i]
		}
	}
	return nil
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

func (e *PostureEngine) authExcluded(path string) bool {
	for _, ex := range e.cfg.Security.Auth.Exclude {
		if ex != "" && strings.HasPrefix(path, ex) {
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
