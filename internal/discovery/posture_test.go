package discovery

import (
	"testing"

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
