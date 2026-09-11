package config

import (
	"strings"
	"testing"
)

// The JWKS document is the trust root for every RSA/ECDSA token the gateway
// accepts. Fetched over http:// an on-path attacker substitutes it, supplies
// their own public key, and mints tokens for any subject with any roles — which
// the gateway then signs into X-Gateway-Signature and hands to backends as
// authenticated identity.
func TestValidate_JWKSURLMustBeHTTPS(t *testing.T) {
	base := func() GatewayConfig {
		c := validBase()
		c.Security.Auth.Enabled = true
		return c
	}

	t.Run("plaintext is refused", func(t *testing.T) {
		c := base()
		c.Security.Auth.JWKSURL = "http://idp.example.com/.well-known/jwks.json"
		err := Validate(c)
		if err == nil {
			t.Fatal("an http:// JWKS URL was accepted; it is the trust root for every token")
		}
		if !strings.Contains(err.Error(), "jwks_url") {
			t.Errorf("the error should name the field, got %v", err)
		}
	})

	t.Run("https is accepted", func(t *testing.T) {
		c := base()
		c.Security.Auth.JWKSURL = "https://idp.example.com/.well-known/jwks.json"
		if err := Validate(c); err != nil {
			t.Fatalf("a valid https JWKS URL was rejected: %v", err)
		}
	})

	// The same dev affordance OIDC has, so a developer can point at a local IdP
	// without weakening the production default.
	t.Run("http allowed only under the local-dev flag", func(t *testing.T) {
		c := base()
		c.Security.Auth.JWKSURL = "http://localhost:8080/jwks"
		c.AdminCookieInsecure = true
		if err := Validate(c); err != nil {
			t.Fatalf("admin_cookie_insecure should permit a local http IdP: %v", err)
		}
	})

	// Anything that is neither is refused too — a bare host, a file path, a
	// scheme the fetcher cannot use.
	t.Run("malformed URLs are refused", func(t *testing.T) {
		for _, u := range []string{"idp.example.com/jwks", "file:///etc/jwks.json", "ftp://x/jwks"} {
			c := base()
			c.Security.Auth.JWKSURL = u
			if err := Validate(c); err == nil {
				t.Errorf("%q was accepted as a JWKS URL", u)
			}
		}
	})

	// Without a JWKS URL the shared-secret rules still apply — this change must
	// not have opened a path where auth is enabled with neither.
	t.Run("no jwks url still requires a secret", func(t *testing.T) {
		c := base()
		c.Security.Auth.JWKSURL = ""
		if err := Validate(c); err == nil {
			t.Fatal("auth enabled with neither jwks_url nor a secret was accepted")
		}
	})
}
