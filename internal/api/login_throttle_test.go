package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// TestLogin_ThrottlesAfterRepeatedFailures verifies the per-IP brute-force gate
// in login() flips to 429 + Retry-After after loginBruteforceLimit consecutive
// failures within the window. Backed by an in-memory Redis (miniredis) so it
// runs in plain `go test ./...` with no external services.
func TestLogin_ThrottlesAfterRepeatedFailures(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	// Use a unique RemoteAddr so the counter is isolated.
	ip := "203.0.113.117:1111"

	post := func() *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"secret": "wrong"})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
		r.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.login(rec, r)
		return rec
	}

	// First N attempts return 401 — credentials wrong but gate not yet tripped.
	for i := 1; i <= loginBruteforceLimit; i++ {
		if code := post().Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, code)
		}
	}
	// One more: gate now denies before doing crypto work.
	rec := post()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", loginBruteforceLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header must be set on throttle response")
	}
}

// TestLogin_AccountLockout_SurvivesIPRotation guards the audit finding that a
// distributed attacker (a fresh source IP per attempt) could brute-force one
// known account indefinitely because the brute-force gate was keyed only by
// IP. Each attempt below uses a unique RemoteAddr — the per-IP gate never
// trips — but all target the same (tenant, email), so the per-account gate
// must trip instead.
func TestLogin_AccountLockout_SurvivesIPRotation(t *testing.T) {
	h := freshHandlers(t)
	h.cfg.AdminAuth = true

	post := func(i int) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"email": "victim@example.com", "password": "wrong"})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
		r.RemoteAddr = "198.51.100." + strconv.Itoa(i) + ":1111" // unique IP every attempt
		rec := httptest.NewRecorder()
		h.login(rec, r)
		return rec
	}

	for i := 1; i <= accountBruteforceLimit; i++ {
		if code := post(i).Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d (fresh IP): got %d, want 401", i, code)
		}
	}
	rec := post(accountBruteforceLimit + 1)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d account-scoped failures despite IP rotation, got %d",
			accountBruteforceLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header must be set on account-lockout throttle response")
	}
}

// TestLogin_ThrottleIsAtomicUnderConcurrency guards VULN H3: a burst of
// concurrent failed-login attempts must not all sail past the brute-force
// gate just because none of them had incremented the counter yet when the
// others checked it. Fire far more than loginBruteforceLimit requests at
// once and assert only loginBruteforceLimit of them ever reach the real
// credential check (401); everything else must be rejected at the gate (429)
// before doing any crypto work.
func TestLogin_ThrottleIsAtomicUnderConcurrency(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true
	ip := "203.0.113.118:2222"

	const burst = 50 // well over loginBruteforceLimit (8)
	var unauthorized, throttled int64
	var wg sync.WaitGroup
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func() {
			defer wg.Done()
			b, _ := json.Marshal(map[string]string{"secret": "wrong"})
			r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
			r.RemoteAddr = ip
			rec := httptest.NewRecorder()
			h.login(rec, r)
			switch rec.Code {
			case http.StatusUnauthorized:
				atomic.AddInt64(&unauthorized, 1)
			case http.StatusTooManyRequests:
				atomic.AddInt64(&throttled, 1)
			default:
				t.Errorf("unexpected status %d", rec.Code)
			}
		}()
	}
	wg.Wait()

	if unauthorized != loginBruteforceLimit {
		t.Fatalf("expected exactly %d requests to reach the credential check under concurrency, got %d (the atomic gate should cap this regardless of how many arrive at once)", loginBruteforceLimit, unauthorized)
	}
	if throttled != burst-loginBruteforceLimit {
		t.Fatalf("expected %d requests throttled, got %d", burst-loginBruteforceLimit, throttled)
	}
}

// TestLogin_StoreOutage_FailOpenByDefault is a regression test for a gap the
// per-IP/per-account brute-force gates had: unlike rate-limit/IPGuard (which
// both expose FailClosed), a Redis outage silently disabled the login gate
// entirely with no way to opt out of that. Default behaviour must still be
// fail-open (an operator can log in during an outage) — this pins that the
// request falls through to the real credential check (401 for a wrong
// secret) rather than erroring, when the store is unreachable.
func TestLogin_StoreOutage_FailOpenByDefault(t *testing.T) {
	h, mr := redisHandlers(t)
	h.cfg.AdminAuth = true
	mr.Close() // simulate a Redis outage: IncrRate now errors

	b, _ := json.Marshal(map[string]string{"secret": "wrong"})
	r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
	r.RemoteAddr = "203.0.113.200:1"
	rec := httptest.NewRecorder()
	h.login(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("store outage, AdminLoginFailClosed=false: got %d, want 401 (fail-open — gate skipped, credential check still ran)", rec.Code)
	}
}

// TestLogin_StoreOutage_FailClosedWhenConfigured is the counterpart: with
// AdminLoginFailClosed set, the same outage must deny the request instead of
// silently leaving /api/login completely unthrottled for the outage's
// duration.
func TestLogin_StoreOutage_FailClosedWhenConfigured(t *testing.T) {
	h, mr := redisHandlers(t)
	h.cfg.AdminAuth = true
	h.cfg.AdminLoginFailClosed = true
	mr.Close()

	b, _ := json.Marshal(map[string]string{"secret": "wrong"})
	r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
	r.RemoteAddr = "203.0.113.201:1"
	rec := httptest.NewRecorder()
	h.login(rec, r)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store outage, AdminLoginFailClosed=true: got %d, want 503 (deny — brute-force budget cannot be enforced)", rec.Code)
	}
}
