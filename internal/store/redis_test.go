package store

import (
	"context"
	"testing"

	"api-gateway/internal/tenant"
)

func TestTKey_TenantScoping(t *testing.T) {
	// Default tenant when unset.
	if got := tkey(context.Background(), "rate:1.2.3.4"); got != "gw:t:default:rate:1.2.3.4" {
		t.Fatalf("default scoping = %q", got)
	}
	// Explicit tenant.
	ctx := tenant.With(context.Background(), "acme")
	if got := tkey(ctx, "blocked_ips"); got != "gw:t:acme:blocked_ips" {
		t.Fatalf("acme scoping = %q", got)
	}
	// Two tenants never collide for the same logical key.
	a := tkey(tenant.With(context.Background(), "acme"), "metrics:x")
	b := tkey(tenant.With(context.Background(), "globex"), "metrics:x")
	if a == b {
		t.Fatalf("tenant keys collided: %q", a)
	}
}
