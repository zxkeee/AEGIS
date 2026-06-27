package iam

import (
	"context"
	"testing"
)

func TestRole_CanMutate(t *testing.T) {
	if !RoleAdmin.CanMutate() {
		t.Fatal("admin must be allowed to mutate")
	}
	if RoleViewer.CanMutate() {
		t.Fatal("viewer must never mutate")
	}
	if Role("unknown").CanMutate() {
		t.Fatal("unknown role must default to no-mutate")
	}
}

func TestFromContext_DefaultsToViewer(t *testing.T) {
	// Absent role => viewer (least privilege). A forgotten WithRole must
	// NEVER silently grant admin.
	if r := FromContext(context.Background()); r != RoleViewer {
		t.Fatalf("default role = %q, want %q", r, RoleViewer)
	}
}

func TestWithRole_RoundTrip(t *testing.T) {
	ctx := WithRole(context.Background(), RoleAdmin)
	if r := FromContext(ctx); r != RoleAdmin {
		t.Fatalf("round-trip = %q, want admin", r)
	}
}

func TestFromContext_EmptyStringFallsBackToViewer(t *testing.T) {
	ctx := WithRole(context.Background(), Role(""))
	if r := FromContext(ctx); r != RoleViewer {
		t.Fatalf("empty role must fall back to viewer, got %q", r)
	}
}

func TestSuperAdmin_Context(t *testing.T) {
	// Default = false (least privilege; an absent SuperAdmin flag must never
	// silently grant cross-tenant powers).
	if IsSuperAdmin(context.Background()) {
		t.Fatal("default IsSuperAdmin must be false")
	}
	ctx := WithSuperAdmin(context.Background(), true)
	if !IsSuperAdmin(ctx) {
		t.Fatal("super-admin not threaded through context")
	}
	ctx = WithSuperAdmin(ctx, false)
	if IsSuperAdmin(ctx) {
		t.Fatal("super-admin flag stuck at true after being cleared")
	}
}
