package config

import (
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
