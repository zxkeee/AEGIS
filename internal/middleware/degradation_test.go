package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// deadStore returns a real *store.Store whose backing Redis has been killed, so
// every call returns a genuine connection error. This is the closest unit-level
// reproduction of a production Redis outage — far more faithful than a fake that
// returns a canned error, because it exercises the actual go-redis error paths.
func deadStore(t *testing.T) *store.Store {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	st, err := store.NewWithConfig(store.SentinelOptions{
		Addr: mr.Addr(),
		// Tight timeouts + no retries so the outage path resolves in ~100ms,
		// keeping the test fast while still exercising the real go-redis error
		// paths the production fail-fast defaults are built on.
		DialTimeout:  100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		MaxRetries:   -1,
	})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mr.Close() // pull the plug — the store now talks to nothing
	return st
}

func okNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func driveReq(h http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	h.ServeHTTP(rec, r)
	return rec
}

// ── Redis outage: the failure-mode matrix, verified end-to-end ───────────────
//
// These lock in the RELEASE-CHECKLIST "graceful failure under load" contract for
// the Redis-unavailable case: enforcement controls in fail_closed mode DENY, the
// same controls in default mode stay AVAILABLE, and nothing panics.

func TestDegrade_RateLimit_FailClosedDenies(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := deadStore(t)
	cfg := config.RateLimitConfig{Enabled: true, Requests: 100, Window: time.Minute, FailClosed: true}
	h := RateLimit(cfg, "test", fakeLogger{}, st)(okNext())
	if code := driveReq(h).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("fail_closed rate limit on outage = %d, want 503", code)
	}
}

func TestDegrade_RateLimit_FailOpenServes(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := deadStore(t)
	cfg := config.RateLimitConfig{Enabled: true, Requests: 100, Window: time.Minute, FailClosed: false}
	h := RateLimit(cfg, "test", fakeLogger{}, st)(okNext())
	if code := driveReq(h).Code; code != http.StatusOK {
		t.Fatalf("fail_open rate limit on outage = %d, want 200 (availability preserved)", code)
	}
}

func TestDegrade_IPGuard_FailClosedDenies(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := deadStore(t)
	cfg := config.IPGuardConfig{Enabled: true, FailClosed: true}
	h := IPGuard(cfg, fakeLogger{}, st)(okNext())
	if code := driveReq(h).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("fail_closed ip-guard on outage = %d, want 503", code)
	}
}

func TestDegrade_IPGuard_FailOpenServes(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := deadStore(t)
	cfg := config.IPGuardConfig{Enabled: true, FailClosed: false}
	h := IPGuard(cfg, fakeLogger{}, st)(okNext())
	if code := driveReq(h).Code; code != http.StatusOK {
		t.Fatalf("fail_open ip-guard on outage = %d, want 200", code)
	}
}

// Even with the dynamic (Redis) block list unreachable, the in-memory static
// blacklist must still be enforced — it does not depend on Redis.
func TestDegrade_IPGuard_StaticBlacklistStillEnforced(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := deadStore(t)
	cfg := config.IPGuardConfig{Enabled: true, Blacklist: []string{"203.0.113.9"}}
	h := IPGuard(cfg, fakeLogger{}, st)(okNext())
	if code := driveReq(h).Code; code != http.StatusForbidden {
		t.Fatalf("static blacklist on outage = %d, want 403", code)
	}
}

// Behavioural scoring is intentionally fail-open: a scoring gap is safer than
// blocking all traffic. Under outage it must serve, not deny, and not panic.
func TestDegrade_Behavior_FailOpenServes(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := deadStore(t)
	cfg := config.BehaviorConfig{Enabled: true, ScoreThreshold: 50, WindowSeconds: 60}
	h := BehaviorAnalysis(cfg, fakeLogger{}, st)(okNext())
	if code := driveReq(h).Code; code != http.StatusOK {
		t.Fatalf("behavior on outage = %d, want 200 (fail-open)", code)
	}
}

// A representative default chain (everything fail-open) must keep serving real
// traffic through a total Redis outage — the core availability guarantee.
func TestDegrade_DefaultChain_StaysAvailable(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := deadStore(t)
	chain := Chain(okNext(),
		IPGuard(config.IPGuardConfig{Enabled: true}, fakeLogger{}, st),
		RateLimit(config.RateLimitConfig{Enabled: true, Requests: 100, Window: time.Minute}, "test", fakeLogger{}, st),
		BehaviorAnalysis(config.BehaviorConfig{Enabled: true, ScoreThreshold: 50, WindowSeconds: 60}, fakeLogger{}, st),
	)
	if code := driveReq(chain).Code; code != http.StatusOK {
		t.Fatalf("default chain on outage = %d, want 200", code)
	}
}
