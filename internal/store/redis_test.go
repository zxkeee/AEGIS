package store

import (
	"context"
	"strings"
	"testing"
	"time"

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

// TestKeyPart_SeparatorCannotShiftFieldBoundaries pins the fix for a collision
// reachable from ordinary request parsing.
//
// Keys join their parts with ":", and several parts come from the request. A
// part containing a colon moved the boundary between fields, so two
// structurally different objects produced one key:
//
//	GET /a/body.foo:123           -> objowner:/a/{id}:body.foo:123
//	GET /a/1  + body {"foo":123}  -> objowner:/a/{id}:body.foo:123
//
// Object ownership is what separates a confirmed IDOR from a caller reading its
// own record, so aliasing onto another key lets a caller be recorded as the
// owner of an object it never owned — and the detection reports nothing.
func TestKeyPart_SeparatorCannotShiftFieldBoundaries(t *testing.T) {
	// The exact pair observed through bolaTargets.
	a := "objowner:" + keyPart("/a/{id}") + ":" + keyPart("body.foo:123")
	b := "objowner:" + keyPart("/a/{id}:body.foo") + ":" + keyPart("123")
	if a == b {
		t.Fatalf("distinct (endpoint, object) pairs still collide on one key: %q", a)
	}

	// The escaping must stay injective, or the collision simply moves: a part
	// that already contains the escape sequence must not decode into another.
	seen := map[string]string{}
	for _, in := range []string{
		"plain", "a:b", "a%3Ab", "a%b", "%3A", "%25", "%253A", "", ":", "::", "%",
	} {
		out := keyPart(in)
		if prev, dup := seen[out]; dup {
			t.Errorf("keyPart(%q) and keyPart(%q) both produce %q", prev, in, out)
		}
		seen[out] = in
		if strings.Contains(out, ":") {
			t.Errorf("keyPart(%q) = %q still contains the separator", in, out)
		}
	}

	// Ordinary parts must pass through untouched, so keys stay readable for an
	// operator reading `redis-cli --scan` output.
	for _, in := range []string{"GET /orders/{id}", "/a/{id}", "42", "token%3Aabc"[:5]} {
		if strings.ContainsAny(in, "%:") {
			continue
		}
		if got := keyPart(in); got != in {
			t.Errorf("keyPart(%q) = %q, want it unchanged", in, got)
		}
	}
}

// The ownership store must not report a binding written for a different object.
func TestObjectOwner_NoCrossObjectAliasing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.SetObjectOwner(ctx, "/a/{id}", "body.foo:123", "attacker", time.Minute); err != nil {
		t.Fatalf("SetObjectOwner: %v", err)
	}
	owner, known, err := s.GetObjectOwner(ctx, "/a/{id}:body.foo", "123")
	if err != nil {
		t.Fatalf("GetObjectOwner: %v", err)
	}
	if known {
		t.Fatalf("a binding written for one object was returned for another (owner=%q): ownership aliasing suppresses confirmed-IDOR detection", owner)
	}
}
