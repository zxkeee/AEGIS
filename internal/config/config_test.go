package config

import (
	"os"
	"strings"
	"testing"
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
