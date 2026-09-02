package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
)

// TestChainSteps_ControlsEnabled exercises the gated branches (auth/WAF/DLP/
// rate-limit force-built) and the anyRoute* helpers, which the order test (all
// controls off) does not reach.
func TestChainSteps_ControlsEnabled(t *testing.T) {
	requireAuth, on := true, true
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			Auth:      config.AuthConfig{Enabled: true, Secret: "test-secret"},
			WAF:       config.WAFConfig{Enabled: true},
			DLP:       config.DLPConfig{Enabled: true},
			RateLimit: config.RateLimitConfig{Enabled: true, Requests: 10, Window: 60},
		},
		Routes: []config.RouteConfig{
			{Path: "/a", RequireAuth: &requireAuth, WAF: &on, DLP: &on,
				RateLimit: &config.RateLimitConfig{Enabled: true, Requests: 5, Window: 60}},
		},
	}
	log := logger.New("error")
	postureEng := discovery.NewPostureEngine(cfg)

	steps := chainSteps(cfg, log, nil, nil, postureEng, nil, nil)
	// The step count is invariant to which controls are active (off controls are
	// passthrough placeholders, not omitted).
	baseline := chainSteps(config.GatewayConfig{}, log, nil, nil, discovery.NewPostureEngine(config.GatewayConfig{}), nil, nil)
	if len(steps) != len(baseline) {
		t.Fatalf("enabled-controls chain has %d steps, baseline %d — count must be invariant", len(steps), len(baseline))
	}
}

// TestChainSteps_RouteOverridesOnly verifies a control can be switched on purely
// by a route override with the global setting off (the anyRoute* true paths).
func TestChainSteps_RouteOverridesOnly(t *testing.T) {
	requireAuth, on := true, true
	cfg := config.GatewayConfig{
		Routes: []config.RouteConfig{
			{Path: "/a", RequireAuth: &requireAuth, WAF: &on, DLP: &on,
				RateLimit: &config.RateLimitConfig{Enabled: true, Requests: 5, Window: 60}},
		},
	}
	if !anyRouteRequiresAuth(cfg.Routes) {
		t.Error("anyRouteRequiresAuth should be true")
	}
	if !anyRouteEnablesRateLimit(cfg.Routes) {
		t.Error("anyRouteEnablesRateLimit should be true")
	}
	if !anyRouteEnablesBool(cfg.Routes, func(r config.RouteConfig) *bool { return r.WAF }) {
		t.Error("anyRouteEnablesBool(WAF) should be true")
	}
	// chainSteps must build with these overrides and a nil store.
	if steps := chainSteps(cfg, logger.New("error"), nil, nil, discovery.NewPostureEngine(cfg), nil, nil); len(steps) == 0 {
		t.Fatal("chainSteps returned no steps")
	}
}

func TestEnforcementSpec(t *testing.T) {
	log := logger.New("error")

	t.Run("disabled returns nil", func(t *testing.T) {
		if s := enforcementSpec(config.GatewayConfig{}, log); s != nil {
			t.Error("disabled enforcement should yield nil spec")
		}
	})

	t.Run("enabled without path returns nil", func(t *testing.T) {
		cfg := config.GatewayConfig{Security: config.SecurityConfig{Schema: config.SchemaConfig{Enabled: true}}}
		if s := enforcementSpec(cfg, log); s != nil {
			t.Error("enabled-but-no-path should yield nil spec")
		}
	})

	t.Run("bad path returns nil", func(t *testing.T) {
		cfg := config.GatewayConfig{
			Security:  config.SecurityConfig{Schema: config.SchemaConfig{Enabled: true}},
			Discovery: config.DiscoveryConfig{SpecPath: "/nonexistent/spec.yaml"},
		}
		if s := enforcementSpec(cfg, log); s != nil {
			t.Error("unreadable spec should yield nil (fail-open)")
		}
	})

	t.Run("valid spec parses", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "openapi.yaml")
		spec := "openapi: 3.0.0\ninfo: {title: t, version: \"1\"}\npaths:\n  /x:\n    get:\n      responses: {\"200\": {description: ok}}\n"
		if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
			t.Fatalf("write spec: %v", err)
		}
		cfg := config.GatewayConfig{
			Security:  config.SecurityConfig{Schema: config.SchemaConfig{Enabled: true}},
			Discovery: config.DiscoveryConfig{SpecPath: path},
		}
		s := enforcementSpec(cfg, log)
		if s == nil || s.OpCount() != 1 {
			t.Fatalf("expected parsed spec with 1 op, got %v", s)
		}
	})
}
