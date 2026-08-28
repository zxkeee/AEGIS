package gateway

import (
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
)

// TestChainOrder pins the data-plane middleware order. The ordering is
// load-bearing (e.g. TenantResolve must be first, CleanHeaders must strip
// spoofed identity before anything trusts it, Discovery must sit inside the
// security perimeter but outside auth/DLP, AbuseDetection must run after auth so
// it sees verified roles). An accidental reorder must fail here, not in prod.
//
// The expected slice intentionally duplicates the wiring in chainSteps: that is
// the point of a golden test — the two must be changed together and a reviewer
// sees the order move explicitly in the diff.
func TestChainOrder(t *testing.T) {
	want := []string{
		"TenantResolve",
		"CleanHeaders",
		"LicenseRateLimit",
		"UpstreamFingerprint",
		"TLSFingerprint",
		"SecurityHeaders",
		"RequestID",
		"PathSanity",
		"CORS",
		"IPGuard",
		"ThreatFeed",
		"RateLimit",
		"BotProtection",
		"Challenge",
		"WAF",
		"Discovery",
		"Auth",
		"SchemaValidation",
		"AbuseDetection",
		"DLP",
		"BehaviorAnalysis",
	}

	cfg := config.GatewayConfig{}
	log := logger.New("error")
	postureEng := discovery.NewPostureEngine(cfg)

	// With every control disabled the constructors return passthrough without
	// ever touching the store, so a nil Store is sufficient to assemble — and
	// pin the order of — the chain without a live Redis.
	steps := chainSteps(cfg, log, nil, nil, postureEng, nil)

	if len(steps) != len(want) {
		t.Fatalf("chain length = %d, want %d", len(steps), len(want))
	}
	for i, s := range steps {
		if s.name != want[i] {
			t.Errorf("chain position %d = %q, want %q", i, s.name, want[i])
		}
	}
}

// TestBuildHandlerChain_NilCatalog ensures a nil *discovery.Catalog yields a
// working handler (the Discovery middleware must degrade to passthrough, not
// panic on a typed-nil interface).
func TestBuildHandlerChain_NilCatalog(t *testing.T) {
	cfg := config.GatewayConfig{
		Routes: []config.RouteConfig{{Path: "/", Upstreams: []string{"http://127.0.0.1:9"}}},
	}
	log := logger.New("error")
	postureEng := discovery.NewPostureEngine(cfg)

	handler, gw, err := BuildHandlerChain(cfg, log, nil, nil, postureEng)
	if err != nil {
		t.Fatalf("BuildHandlerChain: %v", err)
	}
	if handler == nil || gw == nil {
		t.Fatal("BuildHandlerChain returned nil handler or gateway")
	}
}

func TestExactMatchRoutes(t *testing.T) {
	r := func(paths ...string) []config.RouteConfig {
		out := make([]config.RouteConfig, 0, len(paths))
		for _, p := range paths {
			out = append(out, config.RouteConfig{Path: p, Upstreams: []string{"http://127.0.0.1:1"}})
		}
		return out
	}

	tests := []struct {
		name   string
		routes []config.RouteConfig
		want   []string
	}{
		{
			// The footgun itself: item paths under this route 404 at the proxy
			// while the posture engine reports them as covered.
			name:   "collection without trailing slash",
			routes: r("/api/v1/customers"),
			want:   []string{"/api/v1/customers"},
		},
		{
			// Both forms declared — the operator clearly knows the distinction.
			name:   "both forms declared is silent",
			routes: r("/api/v1/orders", "/api/v1/orders/"),
			want:   nil,
		},
		{
			// A single-segment path is idiomatically an exact endpoint.
			name:   "single-segment path is silent",
			routes: r("/health", "/metrics"),
			want:   nil,
		},
		{
			name:   "subtree route is silent",
			routes: r("/internal/"),
			want:   nil,
		},
		{
			// Only the genuine offenders, in declaration order: /api/v1/orders is
			// paired with its subtree form and /health is single-segment.
			name:   "reports every offender and nothing else",
			routes: r("/api/v1/customers", "/api/v1/orders", "/api/v1/orders/", "/health", "/internal/reports"),
			want:   []string{"/api/v1/customers", "/internal/reports"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exactMatchRoutes(tt.routes)
			if len(got) != len(tt.want) {
				t.Fatalf("exactMatchRoutes = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("exactMatchRoutes = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
