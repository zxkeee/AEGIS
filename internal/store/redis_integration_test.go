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
func testStore(t *testing.T) *Store {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR not set; skipping Redis integration test")
	}
	s, err := New(addr, "", 0)
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
