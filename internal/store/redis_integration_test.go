package store

import (
	"context"
	"os"
	"testing"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"
)

// testStore connects to the test Redis or skips when REDIS_ADDR is unset (local
// runs without Redis). CI provides REDIS_ADDR via the redis service.
//
// The password comes from AEGIS_REDIS_PASSWORD, the same variable the gateway
// reads, because the project's own one-command stand (scripts/pentest-stand.sh)
// runs Redis with `requirepass`. Hardcoding an empty password made every test
// here fail against that stand with NOAUTH — an environment failure that reads
// exactly like nine broken tests, which is the expensive kind.
func testStore(t *testing.T) *Store {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR not set; skipping Redis integration test")
	}
	s, err := New(addr, os.Getenv("AEGIS_REDIS_PASSWORD"), 0)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_ = s.client.FlushDB(context.Background()).Err()
	return s
}

func ctxFor(tn string) context.Context { return tenant.With(context.Background(), tn) }

func TestRedis_BlockedIPsIsolated(t *testing.T) {
	s := testStore(t)
	acme, globex := ctxFor("acme"), ctxFor("globex")

	if err := s.BlockIP(acme, "1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	// acme sees its block; globex must not.
	if ok, _ := s.IsIPBlocked(acme, "1.2.3.4"); !ok {
		t.Fatal("acme should see its own blocked IP")
	}
	if ok, _ := s.IsIPBlocked(globex, "1.2.3.4"); ok {
		t.Fatal("globex must NOT see acme's blocked IP (cross-tenant leak)")
	}
	if ips, _ := s.GetBlockedIPs(globex); len(ips) != 0 {
		t.Fatalf("globex blocklist should be empty, got %v", ips)
	}
}

func TestRedis_AutoBanExpiresAndIsUnblockable(t *testing.T) {
	s := testStore(t)
	ctx := ctxFor("acme")

	if err := s.AutoBanIP(ctx, "9.9.9.9", 50*time.Millisecond); err != nil {
		t.Fatalf("AutoBanIP: %v", err)
	}
	if ok, _ := s.IsIPBlocked(ctx, "9.9.9.9"); !ok {
		t.Fatal("IP should be blocked immediately after AutoBanIP")
	}
	if ips, _ := s.GetBlockedIPs(ctx); len(ips) != 1 || ips[0] != "9.9.9.9" {
		t.Fatalf("GetBlockedIPs should list the auto-banned IP, got %v", ips)
	}

	// An admin can lift an auto-ban early via the same UnblockIP path used for
	// permanent blocks — the false-positive escape hatch.
	if err := s.UnblockIP(ctx, "9.9.9.9", ""); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}
	if ok, _ := s.IsIPBlocked(ctx, "9.9.9.9"); ok {
		t.Fatal("IP should be unblocked after UnblockIP")
	}

	// And, independently, the ban self-expires if nobody intervenes.
	if err := s.AutoBanIP(ctx, "8.8.8.8", 50*time.Millisecond); err != nil {
		t.Fatalf("AutoBanIP: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if ok, _ := s.IsIPBlocked(ctx, "8.8.8.8"); ok {
		t.Fatal("auto-ban should have expired on its own")
	}
}

// TestRedis_BlockedIPDetails_DualSourceSelectiveUnblock guards VULN M7: an IP
// that is BOTH manually blocked AND under a live auto-ban must be reported as
// such (so an operator can tell), and unblocking just the "auto" source must
// leave the deliberate manual block in place — not silently lift it.
func TestRedis_BlockedIPDetails_DualSourceSelectiveUnblock(t *testing.T) {
	s := testStore(t)
	ctx := ctxFor("acme")

	if err := s.BlockIP(ctx, "1.1.1.1"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if err := s.AutoBanIP(ctx, "1.1.1.1", time.Minute); err != nil {
		t.Fatalf("AutoBanIP: %v", err)
	}
	details, err := s.GetBlockedIPDetails(ctx)
	if err != nil {
		t.Fatalf("GetBlockedIPDetails: %v", err)
	}
	if len(details) != 1 || details[0].IP != "1.1.1.1" {
		t.Fatalf("expected one entry for 1.1.1.1, got %v", details)
	}
	if details[0].Source != "manual+auto" {
		t.Fatalf("Source = %q, want %q", details[0].Source, "manual+auto")
	}
	if details[0].TTLSeconds <= 0 {
		t.Fatalf("TTLSeconds = %d, want > 0 for a live auto-ban", details[0].TTLSeconds)
	}

	// Unblock only the auto portion — the manual block must survive.
	if err := s.UnblockIP(ctx, "1.1.1.1", "auto"); err != nil {
		t.Fatalf("UnblockIP(auto): %v", err)
	}
	if ok, _ := s.IsIPBlocked(ctx, "1.1.1.1"); !ok {
		t.Fatal("IP should still be blocked — the manual block was not touched")
	}
	details, _ = s.GetBlockedIPDetails(ctx)
	if len(details) != 1 || details[0].Source != "manual" {
		t.Fatalf("expected only the manual block to remain, got %v", details)
	}
}

// TestRedis_AutoBanCounterDoesNotCollideWithBanFlag guards against a real bug
// found while verifying this: the strike counter (IncrAutoBanCounter, used to
// require 3 high-risk hits before banning) and the TTL ban flag (AutoBanIP)
// must live on different Redis keys. They used to share "autoban:<ip>", which
// made IsIPBlocked true after the very FIRST strike instead of the third.
func TestRedis_AutoBanCounterDoesNotCollideWithBanFlag(t *testing.T) {
	s := testStore(t)
	ctx := ctxFor("acme")

	for i := 0; i < 2; i++ {
		if _, err := s.IncrAutoBanCounter(ctx, "5.5.5.5"); err != nil {
			t.Fatalf("IncrAutoBanCounter: %v", err)
		}
	}
	if ok, _ := s.IsIPBlocked(ctx, "5.5.5.5"); ok {
		t.Fatal("two strikes must not block the IP — only AutoBanIP (called on the 3rd) should")
	}

	if err := s.AutoBanIP(ctx, "5.5.5.5", time.Minute); err != nil {
		t.Fatalf("AutoBanIP: %v", err)
	}
	if ok, _ := s.IsIPBlocked(ctx, "5.5.5.5"); !ok {
		t.Fatal("IP should be blocked after AutoBanIP")
	}
}

func TestRedis_MetricsIsolated(t *testing.T) {
	s := testStore(t)
	acme, globex := ctxFor("acme"), ctxFor("globex")

	s.IncrMetric(acme, "blocked_waf")
	s.IncrMetric(acme, "blocked_waf")
	s.IncrMetric(globex, "blocked_waf")

	am, _ := s.GetMetrics(acme)
	gm, _ := s.GetMetrics(globex)
	if am["blocked_waf"] != 2 {
		t.Fatalf("acme metric = %d, want 2", am["blocked_waf"])
	}
	if gm["blocked_waf"] != 1 {
		t.Fatalf("globex metric = %d, want 1 (isolated)", gm["blocked_waf"])
	}
}

func TestRedis_RateLimitIsolated(t *testing.T) {
	s := testStore(t)
	// Same client IP under two tenants must have independent counters.
	c1, _ := s.IncrRate(ctxFor("acme"), "9.9.9.9", time.Minute)
	c2, _ := s.IncrRate(ctxFor("acme"), "9.9.9.9", time.Minute)
	c3, _ := s.IncrRate(ctxFor("globex"), "9.9.9.9", time.Minute)
	if c1 != 1 || c2 != 2 {
		t.Fatalf("acme rate counters = %d,%d want 1,2", c1, c2)
	}
	if c3 != 1 {
		t.Fatalf("globex rate counter = %d, want 1 (independent of acme)", c3)
	}
}

func TestRedis_SessionAndForensicIsolated(t *testing.T) {
	s := testStore(t)
	acme, globex := ctxFor("acme"), ctxFor("globex")

	// Sessions live under a flat key with the tenant inside the payload (so
	// validation can identify which tenant the cookie belongs to without
	// knowing it in advance). The session is therefore visible from any
	// tenant context, but it always reveals its OWN tenant — and AdminAuth
	// then pins the request to that tenant downstream.
	want := iam.Session{CSRF: "csrf1", TenantID: "acme", Role: iam.RoleAdmin}
	if err := s.CreateSession(acme, "tok1", want, time.Minute); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, ok, _ := s.ValidateSession(globex, "tok1")
	if !ok {
		t.Fatal("session must be reachable by token regardless of caller context")
	}
	if got.TenantID != "acme" || got.CSRF != "csrf1" || got.Role != iam.RoleAdmin {
		t.Fatalf("session payload tampered or lost: %+v", got)
	}

	// Forensic log is per-tenant.
	s.PushForensic(acme, ForensicEntry{Tenant: "acme", Reason: "waf", Code: 403})
	if entries, _ := s.GetForensicLog(globex, 100); len(entries) != 0 {
		t.Fatalf("globex forensic log should be empty, got %d", len(entries))
	}
	if entries, _ := s.GetForensicLog(acme, 100); len(entries) != 1 {
		t.Fatalf("acme forensic log should have 1 entry, got %d", len(entries))
	}
}

func TestRedis_ObjectOwnerTracking(t *testing.T) {
	s := testStore(t)
	ctx := ctxFor("acme")
	ep, obj := "GET /api/orders/{id}", "12345"

	// First access by alice: no prior owners, not already owned.
	prior, already, err := s.TrackObjectOwner(ctx, ep, obj, "alice", time.Hour)
	if err != nil {
		t.Fatalf("TrackObjectOwner alice#1: %v", err)
	}
	if prior != 0 || already {
		t.Fatalf("alice first access: prior=%d already=%v, want 0/false", prior, already)
	}

	// Alice re-reads her own object: now she is a known owner.
	prior, already, _ = s.TrackObjectOwner(ctx, ep, obj, "alice", time.Hour)
	if prior != 1 || !already {
		t.Fatalf("alice re-access: prior=%d already=%v, want 1/true", prior, already)
	}

	// Bob reads alice's object: one prior owner (alice), bob not among them —
	// the single-object IDOR signal.
	prior, already, _ = s.TrackObjectOwner(ctx, ep, obj, "bob", time.Hour)
	if prior != 1 || already {
		t.Fatalf("bob cross access: prior=%d already=%v, want 1/false", prior, already)
	}

	// Tenant isolation: globex sees no owners for the same object key.
	prior, already, _ = s.TrackObjectOwner(ctxFor("globex"), ep, obj, "carol", time.Hour)
	if prior != 0 || already {
		t.Fatalf("cross-tenant leak: prior=%d already=%v, want 0/false", prior, already)
	}
}

func TestRedis_ObjectOwnerBinding(t *testing.T) {
	s := testStore(t)
	acme, globex := ctxFor("acme"), ctxFor("globex")
	ep, obj := "GET /api/orders/{id}", "12345"

	// Unknown until set.
	if _, known, err := s.GetObjectOwner(acme, ep, obj); err != nil || known {
		t.Fatalf("unset owner: known=%v err=%v, want false/nil", known, err)
	}

	// Bind the confirmed owner (from a response body).
	if err := s.SetObjectOwner(acme, ep, obj, "alice", time.Hour); err != nil {
		t.Fatalf("SetObjectOwner: %v", err)
	}
	owner, known, err := s.GetObjectOwner(acme, ep, obj)
	if err != nil || !known || owner != "alice" {
		t.Fatalf("GetObjectOwner = %q known=%v err=%v, want alice/true", owner, known, err)
	}

	// Tenant isolation: globex must not see acme's binding.
	if _, known, _ := s.GetObjectOwner(globex, ep, obj); known {
		t.Fatal("cross-tenant owner binding leak")
	}
}
