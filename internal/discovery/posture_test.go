package discovery

import (
	"testing"
	"time"

	"api-gateway/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func newTestEngine() *PostureEngine {
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			WAF:       config.WAFConfig{Enabled: true},
			RateLimit: config.RateLimitConfig{Enabled: true},
			Auth:      config.AuthConfig{Enabled: true, Exclude: []string{"/public"}},
			DLP:       config.DLPConfig{Enabled: true},
			Bot:       config.BotConfig{Enabled: true},
			IPGuard:   config.IPGuardConfig{Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Path: "/api/v1/"}, // inherits global → protected
			{Path: "/public/", RequireAuth: boolPtr(false)}, // explicitly open
			{Path: "/internal/", WAF: boolPtr(false), RateLimit: &config.RateLimitConfig{Enabled: false}, RequireAuth: boolPtr(false)}, // unprotected
		},
	}
	return NewPostureEngine(cfg)
}

func TestClassify(t *testing.T) {
	e := newTestEngine()
	cases := map[string]string{
		"/api/v1/users": PostureProtected,
		"/public/info":  PosturePartial,     // no auth, but WAF+RL still on
		"/internal/db":  PostureUnprotected, // all core off
		"/unknown/path": PostureShadow,      // no matching route
	}
	for path, want := range cases {
		if got := e.Classify(path); got != want {
			t.Errorf("Classify(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestControlsOverride(t *testing.T) {
	e := newTestEngine()
	c, matched := e.ControlsFor("/internal/db")
	if !matched {
		t.Fatal("expected route match for /internal/db")
	}
	if c.WAF || c.RateLimit || c.AuthRequired {
		t.Errorf("expected all core controls off, got %+v", c)
	}
	if !c.DLP {
		t.Error("expected DLP to inherit global (true)")
	}
}

func TestRiskScoreShadowWithPII(t *testing.T) {
	e := newTestEngine()
	low := RiskScore("/api/v1/users", e, EndpointStats{RequestCount: 100})
	high := RiskScore("/unknown/secret", e, EndpointStats{RequestCount: 100, PIICount: 5, AnonCount: 100})
	if high <= low {
		t.Errorf("expected shadow+PII risk (%d) > protected risk (%d)", high, low)
	}
	if low != 0 {
		t.Errorf("fully protected endpoint should be 0 risk, got %d", low)
	}
}

func TestRateLimitFor_RouteOverrideReplacesGlobal(t *testing.T) {
	rl := &config.RateLimitConfig{Enabled: true, Requests: 7, Window: 5 * time.Second}
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			RateLimit: config.RateLimitConfig{Enabled: true, Requests: 100, Window: time.Minute},
		},
		Routes: []config.RouteConfig{
			{Path: "/cheap", RateLimit: rl},
			{Path: "/normal"}, // inherits global
			{Path: "/off", RateLimit: &config.RateLimitConfig{Enabled: false}},
		},
	}
	e := NewPostureEngine(cfg)

	c, key, on := e.RateLimitFor("/cheap")
	if !on || c.Requests != 7 || key != "/cheap" {
		t.Fatalf("/cheap: got on=%v req=%d key=%q, want on=true req=7 key=/cheap", on, c.Requests, key)
	}
	c, key, on = e.RateLimitFor("/normal")
	if !on || c.Requests != 100 || key != "" {
		t.Fatalf("/normal: got on=%v req=%d key=%q, want global 100 with empty key", on, c.Requests, key)
	}
	if _, _, on = e.RateLimitFor("/off"); on {
		t.Fatal("/off: route disabled rate limit, want on=false")
	}
}

// TestMatchRoute_SegmentBoundary is a regression test for a critical bypass:
// matchRoute used to compare paths with a raw strings.HasPrefix, so a
// permissive route like "/api/public" (no trailing slash) would incorrectly
// "cover" an unrelated, longer path like "/api/publicdata/42" that merely
// starts with the same characters — silently handing it the permissive
// route's auth/WAF/DLP/rate-limit posture instead of the global (protected)
// defaults. matchRoute must use config.PathHasPrefix, which requires a "/"
// boundary, exactly like tenant.go and jwt.go's Exclude matching already do.
func TestMatchRoute_SegmentBoundary(t *testing.T) {
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Enabled: true},
			WAF:  config.WAFConfig{Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Path: "/api/public", RequireAuth: boolPtr(false), WAF: boolPtr(false)},
		},
	}
	e := NewPostureEngine(cfg)

	// Exact match and true sub-path: the override legitimately applies.
	for _, p := range []string{"/api/public", "/api/public/info"} {
		c, matched := e.ControlsFor(p)
		if !matched {
			t.Fatalf("ControlsFor(%q): expected a route match", p)
		}
		if c.AuthRequired || c.WAF {
			t.Errorf("ControlsFor(%q) = %+v, want AuthRequired=false WAF=false (route override)", p, c)
		}
	}

	// Adjacent path sharing only a string prefix, no "/" boundary: must NOT
	// inherit /api/public's override. It has no dedicated route, so it falls
	// through to the global (protected) defaults.
	for _, p := range []string{"/api/publicdata/42", "/api/publicity"} {
		c, matched := e.ControlsFor(p)
		if matched {
			t.Errorf("ControlsFor(%q): matched /api/public by raw prefix (segment-boundary regression); want no route match", p)
		}
		if !c.AuthRequired || !c.WAF {
			t.Errorf("ControlsFor(%q) = %+v, want global defaults AuthRequired=true WAF=true — /api/public leaked its override", p, c)
		}
	}
}

// TestMatchRoute_CaseInsensitive is a regression test for a residual variant
// of the same route-prefix bypass TestMatchRoute_SegmentBoundary covers: a
// backend that routes case-insensitively lets a case-varied request path
// ("/Admin", "/ADMIN") slip past a route override keyed on "/admin",
// silently falling back to the (weaker) global posture instead of the
// route's own. matchRoute/authExcluded must lower-case both sides of the
// comparison, exactly like abuse.go's BFLA check already does.
func TestMatchRoute_CaseInsensitive(t *testing.T) {
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Enabled: false},
			WAF:  config.WAFConfig{Enabled: true},
		},
		Routes: []config.RouteConfig{
			{Path: "/Admin", RequireAuth: boolPtr(true), WAF: boolPtr(true)},
		},
	}
	e := NewPostureEngine(cfg)

	for _, p := range []string{"/Admin/users", "/admin/users", "/ADMIN/users"} {
		c, matched := e.ControlsFor(p)
		if !matched {
			t.Fatalf("ControlsFor(%q): expected a route match regardless of case", p)
		}
		if !c.AuthRequired || !c.WAF {
			t.Errorf("ControlsFor(%q) = %+v, want AuthRequired=true WAF=true (route override) — case variation defeated the override", p, c)
		}
	}

	// authExcluded must be equally case-insensitive.
	cfg2 := config.GatewayConfig{
		Security: config.SecurityConfig{Auth: config.AuthConfig{Enabled: true, Exclude: []string{"/public"}}},
	}
	e2 := NewPostureEngine(cfg2)
	for _, p := range []string{"/public/info", "/Public/info", "/PUBLIC/info"} {
		c, _ := e2.ControlsFor(p)
		if c.AuthRequired {
			t.Errorf("ControlsFor(%q) = %+v, want AuthRequired=false (exclude match) — case variation defeated the exclude", p, c)
		}
	}
}
