package gateway

import (
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
)

// The chain order is load-bearing — eight comments in chainSteps say so — and
// until this test nothing checked it. A reordering that broke one of these
// would compile, pass every existing test, and change what the gateway
// actually enforces.
//
// It is not a theoretical risk: two independent descriptions of this
// architecture already disagreed with the code about where Discovery sits.
// Prose drifts; this does not.
//
// Each rule states the consequence of breaking it, because "keep the order"
// with no reason is what gets overridden by the next person with a reason.
func TestChainSteps_OrderIsLoadBearing(t *testing.T) {
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			Auth:      config.AuthConfig{Enabled: true, Secret: "s"},
			WAF:       config.WAFConfig{Enabled: true},
			DLP:       config.DLPConfig{Enabled: true},
			RateLimit: config.RateLimitConfig{Enabled: true},
			IPGuard:   config.IPGuardConfig{Enabled: true},
			Abuse:     config.AbuseConfig{Enabled: true},
			Behavior:  config.BehaviorConfig{Enabled: true},
			Inventory: config.APIInventoryConfig{Enabled: true},
		},
	}
	steps := chainSteps(cfg, logger.New("error"), nil, nil, discovery.NewPostureEngine(cfg), nil, nil)

	pos := make(map[string]int, len(steps))
	for i, s := range steps {
		if _, dup := pos[s.name]; dup {
			t.Fatalf("step %q appears twice; the positions below stop meaning anything", s.name)
		}
		pos[s.name] = i
	}

	rules := []struct{ outer, inner, why string }{
		{"TenantResolve", "CleanHeaders",
			"the tenant must be resolved before anything reads or writes tenant-scoped state"},
		{"TenantResolve", "IPGuard",
			"per-IP state is keyed by tenant; resolving later would read another tenant's blocklist"},
		{"CleanHeaders", "TLSFingerprint",
			"a client-supplied X-JA3-Fingerprint must be stripped before the real one is injected"},
		{"CleanHeaders", "Auth",
			"a spoofed X-Gateway-* must be stripped before anything downstream can trust it"},
		{"CleanHeaders", "LicenseRateLimit",
			"nothing may read a client-supplied forwarding header before CleanHeaders has sanitised the family"},
		{"PathSanity", "CORS",
			"traversal and encoded separators must be rejected before any prefix policy is applied to the path"},
		{"PathSanity", "WAF",
			"the WAF's path rules assume a path that has already been rejected if malformed"},
		{"WAF", "Discovery",
			"a request blocked as an attack must not appear in the catalog; attack noise would pollute the map of the real API"},
		{"Discovery", "Auth",
			"Discovery observes from OUTSIDE auth and is enriched later through the observation pointer in the context — CLAUDE.md described this backwards for some time"},
		{"Discovery", "DLP",
			"Discovery must capture the final status, so it wraps DLP rather than sitting inside it"},
		{"Auth", "ConsumerID",
			"a verified JWT subject must win over an opaque credential when naming the consumer"},
		{"Auth", "AbuseDetection",
			"BOLA/BFLA decisions are made on verified roles; unverified ones would make them meaningless"},
		{"ConsumerID", "AbuseDetection",
			"'did THIS consumer read an object it does not own' has no meaning while every caller is the same ip: consumer"},
		{"RateLimit", "WAF",
			"a flood must be shed before it reaches the most expensive inspection in the chain"},
	}

	for _, r := range rules {
		o, okO := pos[r.outer]
		i, okI := pos[r.inner]
		if !okO {
			t.Errorf("step %q is gone from the chain; the rule %q no longer holds", r.outer, r.why)
			continue
		}
		if !okI {
			t.Errorf("step %q is gone from the chain; the rule %q no longer holds", r.inner, r.why)
			continue
		}
		if o >= i {
			t.Errorf("%s (position %d) must run OUTSIDE %s (position %d): %s",
				r.outer, o, r.inner, i, r.why)
		}
	}
}

// The first step decides what every later step reads. Naming it separately
// means a change to it is a change to this test, not a silent reordering.
func TestChainSteps_TenantResolveIsOutermost(t *testing.T) {
	cfg := config.GatewayConfig{}
	steps := chainSteps(cfg, logger.New("error"), nil, nil, discovery.NewPostureEngine(cfg), nil, nil)
	if len(steps) == 0 {
		t.Fatal("the chain is empty")
	}
	if steps[0].name != "TenantResolve" {
		t.Fatalf("the outermost step is %q, want TenantResolve: every tenant-scoped "+
			"read below it would resolve against the wrong tenant", steps[0].name)
	}
}
