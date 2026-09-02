package sso

import (
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"
)

func auth(cfg config.OIDCConfig) *Authenticator { return &Authenticator{cfg: cfg} }

func TestMapIdentity_AdminAndSuperAdminRoles(t *testing.T) {
	a := auth(config.OIDCConfig{
		RolesClaim:      "groups",
		AdminRoles:      []string{"aegis-admins"},
		SuperAdminRoles: []string{"aegis-superadmins"},
	})

	t.Run("admin group → admin, not super", func(t *testing.T) {
		id, err := a.mapIdentity(map[string]any{
			"email": "Op@Example.com", "groups": []any{"aegis-admins", "other"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.Email != "op@example.com" {
			t.Fatalf("email not normalised: %q", id.Email)
		}
		if id.Role != iam.RoleAdmin || id.SuperAdmin {
			t.Fatalf("want admin/non-super, got %s super=%v", id.Role, id.SuperAdmin)
		}
	})

	t.Run("superadmin group → admin+super, pinned to default tenant", func(t *testing.T) {
		id, err := a.mapIdentity(map[string]any{
			"email": "root@example.com", "groups": []any{"aegis-superadmins"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.Role != iam.RoleAdmin || !id.SuperAdmin {
			t.Fatalf("want admin+super, got %s super=%v", id.Role, id.SuperAdmin)
		}
		if id.TenantID != tenant.Default {
			t.Fatalf("super-admin must pin to default tenant, got %q", id.TenantID)
		}
	})

	t.Run("no matching group → viewer", func(t *testing.T) {
		id, err := a.mapIdentity(map[string]any{
			"email": "user@example.com", "groups": []any{"unrelated"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.Role != iam.RoleViewer || id.SuperAdmin {
			t.Fatalf("want viewer, got %s super=%v", id.Role, id.SuperAdmin)
		}
	})
}

func TestMapIdentity_RequireMappedRoleRejectsUnmapped(t *testing.T) {
	a := auth(config.OIDCConfig{
		RolesClaim: "groups", AdminRoles: []string{"admins"}, RequireMappedRole: true,
	})
	if _, err := a.mapIdentity(map[string]any{
		"email": "user@example.com", "groups": []any{"nope"},
	}); err == nil {
		t.Fatal("unmapped user must be rejected when require_mapped_role is set")
	}
}

func TestMapIdentity_TenantClaim(t *testing.T) {
	a := auth(config.OIDCConfig{RolesClaim: "groups", TenantClaim: "org", AdminRoles: []string{"admins"}})
	id, err := a.mapIdentity(map[string]any{
		"email": "u@example.com", "org": "acme", "groups": []any{"admins"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id.TenantID != "acme" {
		t.Fatalf("tenant claim not honoured: %q", id.TenantID)
	}
}

// TestMapIdentity_AllowedTenants guards VULN M1: without an allowlist, any
// value asserted in TenantClaim is trusted verbatim (auto-provisioning
// whatever tenant it names); with one set, a claim value outside it must be
// refused rather than silently landing the user in — or creating — an
// arbitrary tenant.
func TestMapIdentity_AllowedTenants(t *testing.T) {
	a := auth(config.OIDCConfig{
		RolesClaim: "groups", TenantClaim: "org", AdminRoles: []string{"admins"},
		AllowedTenants: []string{"acme", "globex"},
	})
	if _, err := a.mapIdentity(map[string]any{
		"email": "u@example.com", "org": "not-a-real-tenant", "groups": []any{"admins"},
	}); err == nil {
		t.Fatal("tenant_claim value outside allowed_tenants must be rejected")
	}
	id, err := a.mapIdentity(map[string]any{
		"email": "u@example.com", "org": "acme", "groups": []any{"admins"},
	})
	if err != nil {
		t.Fatalf("allowed tenant rejected: %v", err)
	}
	if id.TenantID != "acme" {
		t.Fatalf("tenant claim not honoured: %q", id.TenantID)
	}
}

func TestMapIdentity_AllowedDomains(t *testing.T) {
	a := auth(config.OIDCConfig{AllowedDomains: []string{"example.com"}})
	if _, err := a.mapIdentity(map[string]any{"email": "u@evil.com"}); err == nil {
		t.Fatal("email outside allowed_domains must be rejected")
	}
	if _, err := a.mapIdentity(map[string]any{"email": "u@example.com"}); err != nil {
		t.Fatalf("allowed domain rejected: %v", err)
	}
}

func TestMapIdentity_RejectsUnverifiedEmailAndMissingEmail(t *testing.T) {
	a := auth(config.OIDCConfig{})
	if _, err := a.mapIdentity(map[string]any{"email": "u@x.com", "email_verified": false}); err == nil {
		t.Fatal("unverified email must be rejected")
	}
	if _, err := a.mapIdentity(map[string]any{"sub": "123"}); err == nil {
		t.Fatal("missing email must be rejected")
	}
}

func TestMapIdentity_RolesClaimAsSingleString(t *testing.T) {
	a := auth(config.OIDCConfig{RolesClaim: "role", AdminRoles: []string{"admin"}})
	id, err := a.mapIdentity(map[string]any{"email": "u@x.com", "role": "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != iam.RoleAdmin {
		t.Fatalf("single-string roles claim not handled: %s", id.Role)
	}
}

func TestNewFlow_UniqueAndPKCEDeterministic(t *testing.T) {
	f1, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	f2, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	if f1.State == f2.State || f1.Nonce == f2.Nonce || f1.CodeVerifier == f2.CodeVerifier {
		t.Fatal("flows must be unique per call")
	}
	// PKCE challenge is a pure function of the verifier (S256): same verifier →
	// same challenge, different verifier → different challenge.
	c1a := pkceChallenge(f1.CodeVerifier)
	c1b := pkceChallenge(f1.CodeVerifier)
	if c1a != c1b {
		t.Fatal("pkce challenge must be deterministic for a verifier")
	}
	if c1a == pkceChallenge(f2.CodeVerifier) {
		t.Fatal("different verifiers must yield different challenges")
	}
}

func TestNormaliseScopes_AlwaysOpenIDOnce(t *testing.T) {
	got := normaliseScopes([]string{"email", "openid", "groups", "email"})
	if got[0] != "openid" {
		t.Fatalf("openid must be first, got %v", got)
	}
	count := 0
	for _, s := range got {
		if s == "openid" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("openid must appear exactly once, got %v", got)
	}
}

func TestMapIdentity_EmailVerifiedStringFalseRejected(t *testing.T) {
	a := auth(config.OIDCConfig{})
	// A provider that sends email_verified as the string "false" must not slip
	// through a bool-only type assertion.
	if _, err := a.mapIdentity(map[string]any{"email": "u@x.com", "email_verified": "false"}); err == nil {
		t.Fatal(`email_verified:"false" (string) must be rejected`)
	}
	// String "true" and absent are accepted.
	if _, err := a.mapIdentity(map[string]any{"email": "u@x.com", "email_verified": "true"}); err != nil {
		t.Fatalf(`email_verified:"true" (string) should pass: %v`, err)
	}
}

// A tenant id from an OIDC claim reaches Redis key namespaces
// (gw:t:<tenant>:...) and the tenants table. The allowlist is optional, so a
// deployment that sets tenant_claim and leaves allowed_tenants empty took
// whatever the provider sent — while the config file and the admin API both
// enforce a shape. One identifier, three doors, one of them unguarded.
func TestMapIdentity_RejectsMalformedTenantClaim(t *testing.T) {
	a := &Authenticator{cfg: config.OIDCConfig{TenantClaim: "org", RolesClaim: "groups"}}

	for _, bad := range []string{
		"acme:evil",             // a separator lands in the key namespace
		"gw:t:acme",             // forges a whole prefix
		"acme/evil",             // path separator
		"acme evil",             // space
		strings.Repeat("a", 65), // over the length bound
	} {
		_, err := a.mapIdentity(map[string]any{"email": "x@acme.io", "org": bad})
		if err == nil {
			t.Errorf("tenant_claim %q was accepted; it becomes a Redis key namespace", bad)
		}
	}

	// A well-formed claim still works, so the check has not closed the feature.
	id, err := a.mapIdentity(map[string]any{"email": "x@acme.io", "org": "acme.corp-1"})
	if err != nil {
		t.Fatalf("a valid tenant claim was rejected: %v", err)
	}
	if id.TenantID != "acme.corp-1" {
		t.Fatalf("tenant = %q, want acme.corp-1", id.TenantID)
	}

	// An absent claim keeps the default tenant, unchanged behaviour.
	id, err = a.mapIdentity(map[string]any{"email": "x@acme.io"})
	if err != nil || id.TenantID != "default" {
		t.Fatalf("absent claim: tenant=%q err=%v, want default", id.TenantID, err)
	}
}
