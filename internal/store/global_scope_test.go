package store

import (
	"context"
	"testing"
	"time"

	"api-gateway/internal/tenant"
)

// The cross-tenant scope used to be selected by the tenant id being the string
// "global". ValidTenantID accepts that string, so an ordinary admin of a tenant
// registered under that name wrote to the cross-tenant namespace on every plain
// block — with no super-admin check in the path. Measured against a live Redis
// before the fix: the victim tenant saw both the block and the revocation.
//
// This test is the fix stated as a property: a tenant id, whatever it spells,
// reaches only its own namespace.
func TestGlobalScope_TenantNamedGlobalCannotCrossTheBoundary(t *testing.T) {
	s := testStore(t)

	victim := tenant.With(context.Background(), "acme")
	impostor := tenant.With(context.Background(), "global")

	if err := s.BlockIP(impostor, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	blocked, err := s.IsIPBlocked(victim, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("a tenant named \"global\" blocked an IP for another tenant")
	}

	if err := s.RevokeJTI(impostor, "jti-cross-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	revoked, err := s.IsJTIRevoked(victim, "jti-cross-1")
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Error("a tenant named \"global\" revoked a JTI for another tenant")
	}
}

// The global scope still has to work, and only through the explicit methods.
func TestGlobalScope_ExplicitMethodsReachEveryTenant(t *testing.T) {
	s := testStore(t)

	admin := context.Background()
	one := tenant.With(context.Background(), "acme")
	two := tenant.With(context.Background(), "globex")

	if err := s.BlockIPGlobal(admin, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for name, ctx := range map[string]context.Context{"acme": one, "globex": two} {
		blocked, err := s.IsIPBlocked(ctx, "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		if !blocked {
			t.Errorf("tenant %s does not see the globally blocked IP", name)
		}
	}

	if err := s.RevokeJTIGlobal(admin, "jti-global-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	revoked, err := s.IsJTIRevoked(one, "jti-global-1")
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("a globally revoked JTI is not revoked for a tenant")
	}

	if err := s.UnblockIPGlobal(admin, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	blocked, err := s.IsIPBlocked(one, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("UnblockIPGlobal left the IP blocked")
	}
}

// A tenant admin has no authority over a global entry. The listing must say so,
// because an unblock that reports success and changes nothing is worse than a
// refusal — it tells the operator the threat is handled when it is not.
func TestGlobalScope_TenantUnblockCannotLiftAGlobalBlock(t *testing.T) {
	s := testStore(t)

	admin := context.Background()
	acme := tenant.With(context.Background(), "acme")

	if err := s.BlockIPGlobal(admin, "203.0.113.11"); err != nil {
		t.Fatal(err)
	}
	if err := s.UnblockIP(acme, "203.0.113.11", "manual"); err != nil {
		t.Fatal(err)
	}
	blocked, err := s.IsIPBlocked(acme, "203.0.113.11")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("a tenant-scoped unblock lifted a global block")
	}

	details, err := s.GetBlockedIPDetails(acme)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range details {
		if d.IP != "203.0.113.11" {
			continue
		}
		found = true
		if !d.Global {
			t.Error("a globally blocked IP is not marked Global in the listing")
		}
	}
	if !found {
		t.Error("a globally blocked IP is missing from the tenant listing")
	}
	if err := s.UnblockIPGlobal(admin, "203.0.113.11"); err != nil {
		t.Fatal(err)
	}
}
