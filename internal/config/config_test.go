package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// validBase returns a configuration that passes Validate, so individual tests
// can mutate one field and assert the resulting rejection.
func validBase() GatewayConfig {
	return GatewayConfig{
		AdminAuth:   true,
		AdminSecret: "a-strong-admin-secret-32-characters!!",
		Redis:       RedisConfig{Password: "redis-pass"},
	}
}

func TestValidate_AcceptsValidConfig(t *testing.T) {
	if err := Validate(validBase()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidate_RejectsEmptyAdminSecret(t *testing.T) {
	c := validBase()
	c.AdminSecret = ""
	if err := Validate(c); err == nil {
		t.Fatal("empty admin secret must be rejected when admin_auth is on")
	}
}

func TestValidate_RejectsShortAutoBanTTL(t *testing.T) {
	c := validBase()
	c.Security.Behavior.Enabled = true
	c.Security.Behavior.WindowSeconds = 60
	c.Security.Behavior.AutoBanTTL = 15 * time.Second
	if err := Validate(c); err == nil {
		t.Fatal("auto_ban_ttl shorter than window_seconds must be rejected (the ban would never actually expire under sustained traffic)")
	}
}

func TestValidate_AcceptsAutoBanTTLAtLeastWindow(t *testing.T) {
	c := validBase()
	c.Security.Behavior.Enabled = true
	c.Security.Behavior.WindowSeconds = 60
	c.Security.Behavior.AutoBanTTL = 30 * time.Minute
	if err := Validate(c); err != nil {
		t.Fatalf("auto_ban_ttl >= window_seconds should be accepted: %v", err)
	}
}

func TestValidate_RejectsPlaceholderSecret(t *testing.T) {
	c := validBase()
	c.AdminSecret = "changeme"
	if err := Validate(c); err == nil {
		t.Fatal("placeholder admin secret must be rejected")
	}
}

func TestValidate_RejectsShortSecret(t *testing.T) {
	c := validBase()
	c.AdminSecret = "tooshort"
	if err := Validate(c); err == nil {
		t.Fatal("short admin secret must be rejected")
	}
}

func TestValidate_RejectsEmptyRedisPassword(t *testing.T) {
	c := validBase()
	c.Redis.Password = ""
	if err := Validate(c); err == nil {
		t.Fatal("empty Redis password must be flagged")
	}
}

func TestValidate_RejectsWildcardCORSWithAuth(t *testing.T) {
	c := validBase()
	c.Security.Auth.Enabled = true
	c.Security.CORS.Enabled = true
	c.Security.CORS.AllowOrigins = []string{"*"}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "CORS") {
		t.Fatalf("wildcard CORS with auth must be rejected, got %v", err)
	}
}

func TestValidate_RejectsNonHTTPSThreatFeed(t *testing.T) {
	c := validBase()
	c.Security.ThreatFeed.Enabled = true
	c.Security.ThreatFeed.URL = "http://feed.example/blocklist.txt"
	if err := Validate(c); err == nil {
		t.Fatal("non-HTTPS threat feed URL must be rejected")
	}
}

func TestValidate_RejectsInvalidTrustedProxy(t *testing.T) {
	c := validBase()
	c.TrustedProxies = []string{"definitely-not-an-ip"}
	if err := Validate(c); err == nil {
		t.Fatal("invalid trusted proxy must be rejected")
	}
}

func TestValidate_RejectsInvalidIPGuardWhitelistEntry(t *testing.T) {
	c := validBase()
	c.Security.IPGuard.Whitelist = []string{"not-an-ip-or-cidr"}
	if err := Validate(c); err == nil {
		t.Fatal("invalid ip_guard.whitelist entry must be rejected")
	}
}

func TestValidate_RejectsInvalidIPGuardBlacklistEntry(t *testing.T) {
	c := validBase()
	c.Security.IPGuard.Blacklist = []string{"999.999.999.999"}
	if err := Validate(c); err == nil {
		t.Fatal("invalid ip_guard.blacklist entry must be rejected")
	}
}

func TestValidate_AcceptsIPGuardCIDREntries(t *testing.T) {
	c := validBase()
	c.Security.IPGuard.Whitelist = []string{"10.0.0.0/8", "192.168.1.1"}
	c.Security.IPGuard.Blacklist = []string{"2001:db8::/32"}
	if err := Validate(c); err != nil {
		t.Fatalf("valid CIDR/IP entries should be accepted: %v", err)
	}
}

func TestValidate_RejectsRegistryEnabled(t *testing.T) {
	c := validBase()
	c.Registry.Enabled = true
	if err := Validate(c); err == nil {
		t.Fatal("registry.enabled: true must be rejected — ServiceAuth is not wired into the request path")
	}
}

func TestValidate_AcceptsRegistryDisabled(t *testing.T) {
	c := validBase()
	c.Registry.Enabled = false
	if err := Validate(c); err != nil {
		t.Fatalf("registry.enabled: false should be accepted: %v", err)
	}
}

func TestValidate_JWTSecretRequiredWithoutJWKS(t *testing.T) {
	c := validBase()
	c.Security.Auth.Enabled = true
	c.Security.Auth.Secret = "" // no JWKS, no secret
	if err := Validate(c); err == nil {
		t.Fatal("auth enabled without jwks_url or secret must be rejected")
	}
}

func TestValidate_JWKSURLSatisfiesAuth(t *testing.T) {
	c := validBase()
	c.Security.Auth.Enabled = true
	c.Security.Auth.JWKSURL = "https://issuer.example/.well-known/jwks.json"
	if err := Validate(c); err != nil {
		t.Fatalf("JWKS URL should satisfy auth validation, got %v", err)
	}
}

func TestValidate_PropagationSecretOptional(t *testing.T) {
	c := validBase()
	c.Security.Auth.PropagationSecret = "" // falls back to auth.secret, not required
	if err := Validate(c); err != nil {
		t.Fatalf("empty propagation_secret should be accepted (falls back to auth.secret), got %v", err)
	}
}

func TestValidate_RejectsPlaceholderPropagationSecret(t *testing.T) {
	c := validBase()
	c.Security.Auth.PropagationSecret = "changeme"
	if err := Validate(c); err == nil {
		t.Fatal("placeholder propagation_secret must be rejected")
	}
}

func TestValidate_RejectsShortPropagationSecret(t *testing.T) {
	c := validBase()
	c.Security.Auth.PropagationSecret = "too-short"
	if err := Validate(c); err == nil {
		t.Fatal("propagation_secret under 32 chars must be rejected")
	}
}

func TestValidate_AcceptsStrongPropagationSecret(t *testing.T) {
	c := validBase()
	// A genuinely random-looking 32+ char secret, not strings.Repeat("a", 32) —
	// that fixture used to pass only because Validate checked length and a
	// literal placeholder list, not entropy; it is exactly the low-entropy
	// shape looksLowEntropy now rejects (see TestValidate_RejectsLowEntropySecret).
	c.Security.Auth.PropagationSecret = "9f3a7c1e5b8d2046af71c3e9b05d8f42"
	if err := Validate(c); err != nil {
		t.Fatalf("strong propagation_secret should be accepted, got %v", err)
	}
}

// TestValidate_RejectsLowEntropySecret is a regression test for the secret-scan
// finding that placeholder rejection was exact-string-match only: a value long
// enough to pass the 32-char floor and absent from insecurePlaceholders — a
// run of one character, or a short repeating cycle — used to be accepted.
func TestValidate_RejectsLowEntropySecret(t *testing.T) {
	cases := map[string]string{
		"admin_secret":       strings.Repeat("a", 32),
		"auth.secret":        strings.Repeat("ab", 16), // short repeating cycle
		"propagation_secret": strings.Repeat("x", 40),
	}
	for name, secret := range cases {
		c := validBase()
		switch name {
		case "admin_secret":
			c.AdminSecret = secret
		case "auth.secret":
			c.Security.Auth.Enabled = true
			c.Security.Auth.Secret = secret
		case "propagation_secret":
			c.Security.Auth.PropagationSecret = secret
		}
		if err := Validate(c); err == nil {
			t.Errorf("%s = %q: low-entropy secret should be rejected, got nil error", name, secret)
		}
	}
}

func TestValidate_Alerting(t *testing.T) {
	t.Run("valid slack/critical", func(t *testing.T) {
		c := validBase()
		c.Alerting = AlertingConfig{WebhookURL: "https://hooks.slack.com/x", Format: "slack", MinSeverity: "critical"}
		if err := Validate(c); err != nil {
			t.Fatalf("valid alerting rejected: %v", err)
		}
	})
	t.Run("bad format", func(t *testing.T) {
		c := validBase()
		c.Alerting.Format = "xml"
		if err := Validate(c); err == nil {
			t.Fatal("invalid alerting.format must be rejected")
		}
	})
	t.Run("bad severity", func(t *testing.T) {
		c := validBase()
		c.Alerting.MinSeverity = "loud"
		if err := Validate(c); err == nil {
			t.Fatal("invalid alerting.min_severity must be rejected")
		}
	})
	t.Run("bad url scheme", func(t *testing.T) {
		c := validBase()
		c.Alerting.WebhookURL = "ftp://example/hook"
		if err := Validate(c); err == nil {
			t.Fatal("non-http(s) webhook url must be rejected")
		}
	})
}

func TestValidate_RedisSentinel(t *testing.T) {
	t.Run("valid sentinel mode", func(t *testing.T) {
		c := validBase()
		c.Redis.Sentinel = SentinelConfig{
			MasterName: "mymaster",
			Addrs:      []string{"sentinel-1:26379", "sentinel-2:26379"},
		}
		if err := Validate(c); err != nil {
			t.Fatalf("valid sentinel rejected: %v", err)
		}
	})
	t.Run("master name without addrs", func(t *testing.T) {
		c := validBase()
		c.Redis.Sentinel.MasterName = "mymaster"
		if err := Validate(c); err == nil {
			t.Fatal("master_name without addrs must be rejected")
		}
	})
	t.Run("addrs without master name", func(t *testing.T) {
		c := validBase()
		c.Redis.Sentinel.Addrs = []string{"sentinel-1:26379"}
		if err := Validate(c); err == nil {
			t.Fatal("addrs without master_name must be rejected")
		}
	})
}

func TestValidate_Multitenancy(t *testing.T) {
	base := func() GatewayConfig {
		c := validBase()
		c.Multitenancy = MultitenancyConfig{
			Enabled: true,
			Tenants: []TenantConfig{{ID: "acme", Hosts: []string{"acme.example"}}},
		}
		c.Routes = []RouteConfig{{Path: "/orders", TenantID: "acme", Upstreams: []string{"http://up"}}}
		return c
	}

	t.Run("valid", func(t *testing.T) {
		if err := Validate(base()); err != nil {
			t.Fatalf("valid multitenancy rejected: %v", err)
		}
	})
	t.Run("disabled needs no tenant_id", func(t *testing.T) {
		c := validBase()
		c.Routes = []RouteConfig{{Path: "/x", Upstreams: []string{"http://up"}}}
		if err := Validate(c); err != nil {
			t.Fatalf("single-tenant route rejected: %v", err)
		}
	})
	t.Run("enabled but no tenants", func(t *testing.T) {
		c := base()
		c.Multitenancy.Tenants = nil
		if err := Validate(c); err == nil {
			t.Fatal("enabled MT without tenants must be rejected")
		}
	})
	t.Run("route references unknown tenant", func(t *testing.T) {
		c := base()
		c.Routes[0].TenantID = "ghost"
		if err := Validate(c); err == nil {
			t.Fatal("route with unknown tenant must be rejected")
		}
	})
	t.Run("route missing tenant_id", func(t *testing.T) {
		c := base()
		c.Routes[0].TenantID = ""
		if err := Validate(c); err == nil {
			t.Fatal("route without tenant_id must be rejected when MT enabled")
		}
	})
	t.Run("duplicate tenant id", func(t *testing.T) {
		c := base()
		c.Multitenancy.Tenants = append(c.Multitenancy.Tenants, TenantConfig{ID: "acme"})
		if err := Validate(c); err == nil {
			t.Fatal("duplicate tenant id must be rejected")
		}
	})
	t.Run("host mapped to two tenants", func(t *testing.T) {
		c := base()
		c.Multitenancy.Tenants = append(c.Multitenancy.Tenants,
			TenantConfig{ID: "globex", Hosts: []string{"acme.example"}})
		if err := Validate(c); err == nil {
			t.Fatal("host collision across tenants must be rejected")
		}
	})
	t.Run("reserved default id", func(t *testing.T) {
		c := base()
		c.Multitenancy.Tenants[0].ID = "default"
		c.Routes[0].TenantID = "default"
		if err := Validate(c); err == nil {
			t.Fatal("reserved tenant id 'default' must be rejected")
		}
	})
}

func TestLoad_AlertingDefaults(t *testing.T) {
	path := t.TempDir() + "/gw.yaml"
	if err := os.WriteFile(path, []byte("listen: \":8080\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Alerting.Format != "generic" || cfg.Alerting.MinSeverity != "warning" {
		t.Fatalf("unexpected alerting defaults: %+v", cfg.Alerting)
	}
}

func TestPathHasPrefix_SegmentBoundary(t *testing.T) {
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{"/public", "/public", true},
		{"/public/x", "/public", true},
		{"/publicXYZ", "/public", false}, // the bug: must NOT match
		{"/public/", "/public/", true},
		{"/api/v1/users", "/api/v1", true},
		{"/api/v10/users", "/api/v1", false},
		{"/anything", "", false},
		{"/health", "/healthz", false},
	}
	for _, c := range cases {
		if got := PathHasPrefix(c.path, c.prefix); got != c.want {
			t.Errorf("PathHasPrefix(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
		}
	}
}

func TestValidate_Routes(t *testing.T) {
	t.Run("unknown load_balance rejected", func(t *testing.T) {
		cfg := validBase()
		cfg.Routes = []RouteConfig{{Path: "/x", Upstreams: []string{"http://b:1"}, LoadBalance: "least_conn"}}
		if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "load_balance") {
			t.Fatalf("unsupported load_balance must be rejected, got %v", err)
		}
	})
	t.Run("round_robin and empty accepted", func(t *testing.T) {
		cfg := validBase()
		cfg.Routes = []RouteConfig{
			{Path: "/a", Upstreams: []string{"http://b:1"}, LoadBalance: "round_robin"},
			{Path: "/b", Upstreams: []string{"http://b:2"}},
		}
		if err := Validate(cfg); err != nil {
			t.Fatalf("valid routes rejected: %v", err)
		}
	})
	t.Run("invalid timeout rejected", func(t *testing.T) {
		cfg := validBase()
		cfg.Routes = []RouteConfig{{Path: "/x", Upstreams: []string{"http://b:1"}, Timeout: "half-an-hour"}}
		if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("invalid route timeout must be rejected, got %v", err)
		}
	})
}

func TestValidate_AdminCORSWildcardRejected(t *testing.T) {
	cfg := validBase()
	cfg.AdminCORS = &CORSConfig{Enabled: true, AllowOrigins: []string{"*"}}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "admin_cors") {
		t.Fatalf("wildcard admin_cors with admin_auth must be rejected, got %v", err)
	}
	// Explicit origins are fine.
	cfg.AdminCORS = &CORSConfig{Enabled: true, AllowOrigins: []string{"https://console.example.com"}}
	if err := Validate(cfg); err != nil {
		t.Fatalf("explicit admin_cors origin rejected: %v", err)
	}
}

func oidcBase() GatewayConfig {
	c := validBase()
	c.ForensicDSN = "postgres://x/y"
	c.OIDC = OIDCConfig{
		Enabled:      true,
		Issuer:       "https://idp.example.com",
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURL:  "https://console.example.com/api/auth/oidc/callback",
		AdminRoles:   []string{"aegis-admins"}, // an access restriction (now required)
	}
	return c
}

func TestValidate_OIDC(t *testing.T) {
	if err := Validate(oidcBase()); err != nil {
		t.Fatalf("valid oidc config rejected: %v", err)
	}

	t.Run("requires admin_auth", func(t *testing.T) {
		c := oidcBase()
		c.AdminAuth = false
		c.AdminSecret = ""
		if err := Validate(c); err == nil || !strings.Contains(err.Error(), "admin_auth") {
			t.Fatalf("oidc without admin_auth must be rejected, got %v", err)
		}
	})
	t.Run("requires forensic_dsn", func(t *testing.T) {
		c := oidcBase()
		c.ForensicDSN = ""
		if err := Validate(c); err == nil || !strings.Contains(err.Error(), "forensic_dsn") {
			t.Fatalf("oidc without forensic_dsn must be rejected, got %v", err)
		}
	})
	t.Run("issuer must be https", func(t *testing.T) {
		c := oidcBase()
		c.OIDC.Issuer = "http://idp.example.com"
		if err := Validate(c); err == nil || !strings.Contains(err.Error(), "issuer") {
			t.Fatalf("non-https issuer must be rejected, got %v", err)
		}
	})
	t.Run("client id/secret required", func(t *testing.T) {
		c := oidcBase()
		c.OIDC.ClientID = ""
		if err := Validate(c); err == nil {
			t.Fatal("missing client_id must be rejected")
		}
		c = oidcBase()
		c.OIDC.ClientSecret = ""
		if err := Validate(c); err == nil {
			t.Fatal("missing client_secret must be rejected")
		}
	})
	t.Run("redirect must be https callback path", func(t *testing.T) {
		c := oidcBase()
		c.OIDC.RedirectURL = "https://console.example.com/wrong"
		if err := Validate(c); err == nil || !strings.Contains(err.Error(), "callback") {
			t.Fatalf("redirect not ending in the callback path must be rejected, got %v", err)
		}
		c = oidcBase()
		c.OIDC.RedirectURL = "http://console.example.com/api/auth/oidc/callback"
		if err := Validate(c); err == nil {
			t.Fatal("http redirect must be rejected unless admin_cookie_insecure")
		}
		c.AdminCookieInsecure = true
		if err := Validate(c); err != nil {
			t.Fatalf("http redirect with admin_cookie_insecure should pass: %v", err)
		}
	})
}

func TestApplyEnvOverrides_OIDCSecrets(t *testing.T) {
	t.Setenv("AEGIS_OIDC_CLIENT_ID", "env-cid")
	t.Setenv("AEGIS_OIDC_CLIENT_SECRET", "env-secret")
	c := GatewayConfig{}
	applyEnvOverrides(&c)
	if c.OIDC.ClientID != "env-cid" || c.OIDC.ClientSecret != "env-secret" {
		t.Fatalf("oidc secrets not overridden from env: %+v", c.OIDC)
	}
}

func TestApplyEnvOverrides_RedisSentinelPassword(t *testing.T) {
	t.Setenv("AEGIS_REDIS_SENTINEL_PASSWORD", "env-sentinel-pass")
	c := GatewayConfig{}
	applyEnvOverrides(&c)
	if c.Redis.Sentinel.SentinelPassword != "env-sentinel-pass" {
		t.Fatalf("sentinel password not overridden from env: %+v", c.Redis.Sentinel)
	}
}

func TestValidate_Retention(t *testing.T) {
	base := func() GatewayConfig {
		c := validBase()
		c.ForensicDSN = "postgres://x/y"
		c.Retention = RetentionConfig{Enabled: true, ForensicDays: 90}
		return c
	}
	if err := Validate(base()); err != nil {
		t.Fatalf("valid retention rejected: %v", err)
	}
	t.Run("requires forensic_dsn", func(t *testing.T) {
		c := base()
		c.ForensicDSN = ""
		if err := Validate(c); err == nil || !strings.Contains(err.Error(), "forensic_dsn") {
			t.Fatalf("retention without forensic_dsn must be rejected, got %v", err)
		}
	})
	t.Run("all-zero windows rejected", func(t *testing.T) {
		c := base()
		c.Retention = RetentionConfig{Enabled: true}
		if err := Validate(c); err == nil || !strings.Contains(err.Error(), "window") {
			t.Fatalf("enabled with no window must be rejected, got %v", err)
		}
	})
	t.Run("negative window rejected", func(t *testing.T) {
		c := base()
		c.Retention.AuditDays = -1
		if err := Validate(c); err == nil {
			t.Fatal("negative window must be rejected")
		}
	})
	t.Run("disabled is a no-op", func(t *testing.T) {
		c := validBase()
		c.Retention = RetentionConfig{Enabled: false, ForensicDays: -5} // ignored when disabled
		if err := Validate(c); err != nil {
			t.Fatalf("disabled retention should not validate its fields: %v", err)
		}
	})
}

func TestLoad_RetentionIntervalDefault(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/g.yaml"
	if err := os.WriteFile(p, []byte(`
admin_auth: true
admin_secret: "a-strong-admin-secret-32-characters!!"
forensic_dsn: "postgres://x/y"
redis: {password: "p"}
retention:
  enabled: true
  forensic_days: 30
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Retention.Interval != 24*time.Hour {
		t.Fatalf("interval default = %v, want 24h", c.Retention.Interval)
	}
}

func TestValidate_OIDCRequiresAccessRestriction(t *testing.T) {
	c := oidcBase()
	c.OIDC.AdminRoles = nil
	c.OIDC.SuperAdminRoles = nil
	c.OIDC.AllowedDomains = nil
	c.OIDC.RequireMappedRole = false
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "access restriction") {
		t.Fatalf("OIDC with no restriction must be rejected, got %v", err)
	}
	// Any single restriction satisfies it.
	for _, set := range []func(*OIDCConfig){
		func(o *OIDCConfig) { o.AdminRoles = []string{"a"} },
		func(o *OIDCConfig) { o.SuperAdminRoles = []string{"s"} },
		func(o *OIDCConfig) { o.AllowedDomains = []string{"example.com"} },
		func(o *OIDCConfig) { o.RequireMappedRole = true },
	} {
		c := oidcBase()
		c.OIDC.AdminRoles, c.OIDC.SuperAdminRoles, c.OIDC.AllowedDomains, c.OIDC.RequireMappedRole = nil, nil, nil, false
		set(&c.OIDC)
		if err := Validate(c); err != nil {
			t.Fatalf("one restriction should satisfy validation: %v", err)
		}
	}
}

// TestApplyObserveMode verifies the pilot/passive coercion: every blocking or
// modifying behaviour is turned off while the detection controls stay enabled.
func TestApplyObserveMode(t *testing.T) {
	cfg := GatewayConfig{
		Observe: true,
		Routes:  []RouteConfig{{Path: "/x", RateLimit: &RateLimitConfig{Enabled: true}}},
		Security: SecurityConfig{
			WAF:        WAFConfig{Enabled: true, BlockMode: true, FailClosed: true},
			Schema:     SchemaConfig{Enabled: true, BlockMode: true},
			Abuse:      AbuseConfig{Enabled: true, BlockMode: true, ObjectOwnershipBlock: true},
			DLP:        DLPConfig{Enabled: true},
			Auth:       AuthConfig{Enabled: true, RevocationFailClosed: true},
			RateLimit:  RateLimitConfig{Enabled: true, FailClosed: true},
			IPGuard:    IPGuardConfig{Enabled: true, FailClosed: true},
			ThreatFeed: ThreatFeedConfig{Enabled: true},
			Bot:        BotConfig{Enabled: true},
			Challenge:  ChallengeConfig{Enabled: true},
			Behavior:   BehaviorConfig{Enabled: true},
		},
	}
	changed := cfg.ApplyObserveMode()
	if len(changed) == 0 {
		t.Fatal("ApplyObserveMode reported no changes on an enforcing config")
	}
	s := cfg.Security

	// Detection controls: still enabled, but never blocking / modifying.
	if s.WAF.BlockMode || s.Schema.BlockMode || s.Abuse.BlockMode || s.Abuse.ObjectOwnershipBlock {
		t.Error("a block_mode remained set")
	}
	if !s.WAF.Enabled || !s.Schema.Enabled || !s.Abuse.Enabled || !s.DLP.Enabled || !s.Auth.Enabled {
		t.Error("a detection control was disabled (should stay on)")
	}
	if !s.DLP.Observe {
		t.Error("dlp.Observe not set")
	}
	if !s.Auth.Observe {
		t.Error("auth.Observe not set")
	}
	if !s.WAF.Observe {
		t.Error("waf.Observe not set (built-in rules would still block via inline deny)")
	}

	// Enforcement-only controls: disabled.
	if s.RateLimit.Enabled || s.IPGuard.Enabled || s.ThreatFeed.Enabled || s.Bot.Enabled || s.Challenge.Enabled || s.Behavior.Enabled {
		t.Error("an enforcement-only control remained enabled")
	}
	// Per-route rate-limit override cleared.
	if cfg.Routes[0].RateLimit != nil {
		t.Error("per-route rate_limit override was not cleared")
	}
	// Never fail closed. (VULN-903: s.WAF.FailClosed was added to
	// ApplyObserveMode without corresponding test coverage — a pilot deployment
	// must never 503 all data-plane traffic just because the WAF engine failed
	// to build.)
	if s.RateLimit.FailClosed || s.IPGuard.FailClosed || s.Auth.RevocationFailClosed || s.WAF.FailClosed {
		t.Error("a fail_closed flag remained set")
	}

	// Observe off = no-op.
	plain := GatewayConfig{Security: SecurityConfig{WAF: WAFConfig{Enabled: true, BlockMode: true}}}
	if got := plain.ApplyObserveMode(); got != nil {
		t.Fatalf("ApplyObserveMode with Observe=false should be a no-op, got %v", got)
	}
	if !plain.Security.WAF.BlockMode {
		t.Error("Observe=false must not change anything")
	}
}

// Duplicate route paths used to reach http.ServeMux, which PANICS on a
// conflicting pattern — inside proxy.New, called by the hot-reload goroutine
// with nothing recovering it. An operator typo in a live config therefore
// killed the process instead of being rejected. Validate must catch it first.
func TestValidate_RejectsDuplicateRoutePath(t *testing.T) {
	c := validBase()
	c.Routes = []RouteConfig{
		{Path: "/orders", Upstreams: []string{"http://a:1"}},
		{Path: "/orders", Upstreams: []string{"http://b:2"}},
	}
	err := Validate(c)
	if err == nil {
		t.Fatal("duplicate route path must be rejected (it panics http.ServeMux)")
	}
	if !strings.Contains(err.Error(), "/orders") {
		t.Fatalf("error must name the offending route, got: %v", err)
	}
}

// A route path unique per tenant is the supported shape and must still pass.
func TestValidate_AcceptsDistinctPathsPerTenant(t *testing.T) {
	c := validBase()
	c.Multitenancy = MultitenancyConfig{
		Enabled: true,
		Tenants: []TenantConfig{{ID: "acme"}, {ID: "globex"}},
	}
	c.Routes = []RouteConfig{
		{Path: "/acme/orders", TenantID: "acme", Upstreams: []string{"http://a:1"}},
		{Path: "/globex/orders", TenantID: "globex", Upstreams: []string{"http://b:2"}},
	}
	if err := Validate(c); err != nil {
		t.Fatalf("distinct paths per tenant must be accepted: %v", err)
	}
}

// Two tenants sharing one path is the natural way to express multitenancy
// model A (route by Host), but the proxy keys on path alone so it cannot work.
// The rejection must say that, not report a generic duplicate — otherwise the
// operator reads it as a typo and retries the same thing.
func TestValidate_RejectsSamePathAcrossTenants(t *testing.T) {
	c := validBase()
	c.Multitenancy = MultitenancyConfig{
		Enabled: true,
		Tenants: []TenantConfig{
			{ID: "acme", Hosts: []string{"acme.example"}},
			{ID: "globex", Hosts: []string{"globex.example"}},
		},
	}
	c.Routes = []RouteConfig{
		{Path: "/orders", TenantID: "acme", Upstreams: []string{"http://a:1"}},
		{Path: "/orders", TenantID: "globex", Upstreams: []string{"http://b:2"}},
	}
	err := Validate(c)
	if err == nil {
		t.Fatal("two tenants sharing one route path must be rejected")
	}
	for _, want := range []string{"acme", "globex", "cannot share one path"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must explain the tenant collision (missing %q), got: %v", want, err)
		}
	}
}
