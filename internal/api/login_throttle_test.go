package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain disables the real bootstrapSecretDelay sleep for every test in
// this package. The ladder's actual DURATIONS are covered directly (and
// quickly) by TestBootstrapSecretDelay_Ladder; handler-level tests below only
// need to know the throttle path was TAKEN (via the
// admin_bootstrap_secret_throttled metric), not spend real wall-clock time
// sleeping through it — several of them deliberately drive the counter past
// every rung of the ladder.
func TestMain(m *testing.M) {
	bootstrapSecretSleep = func(context.Context, time.Duration) {}
	m.Run()
}

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

// TestLogin_BootstrapSecret_NeverGloballyLocksOut is a regression test for
// VULN-802's fix: the cross-IP telemetry counter on the {"secret": ...}
// bootstrap path must NEVER deny a correct secret, no matter how many failed
// guesses (from any number of distinct IPs) preceded it. A blocking gate here
// would let an unauthenticated caller lock every admin out with a handful of
// requests, since — unlike email/password — there is only one bootstrap
// secret shared by the whole deployment.
func TestLogin_BootstrapSecret_NeverGloballyLocksOut(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	failFromIP := func(i int) int {
		b, _ := json.Marshal(map[string]string{"secret": "wrong"})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
		r.RemoteAddr = "198.51.100." + strconv.Itoa(i) + ":1111" // unique IP every attempt
		rec := httptest.NewRecorder()
		h.login(rec, r)
		return rec.Code
	}

	// Well over bootstrapSecretBruteforceLimit, each from a fresh IP so the
	// per-IP gate (also fresh per IP) never trips either — isolates the
	// bootstrap-secret telemetry path specifically.
	attempts := bootstrapSecretBruteforceLimit + 10
	for i := 1; i <= attempts; i++ {
		if code := failFromIP(i); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401 (wrong secret, gate must not block)", i, code)
		}
	}

	// The correct secret, from yet another fresh IP, must still succeed.
	b, _ := json.Marshal(map[string]string{"secret": h.cfg.AdminSecret})
	r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
	r.RemoteAddr = "198.51.100.250:1111"
	rec := httptest.NewRecorder()
	h.login(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct bootstrap secret after %d cross-IP failures: got %d, want 200 (telemetry gate must never block a correct secret)",
			attempts, rec.Code)
	}
}

// TestBootstrapSecretDelay_Ladder pins the VULN-904 throttle ladder directly,
// independent of TestMain's stubbed sleep — this is what actually governs
// production behavior.
func TestBootstrapSecretDelay_Ladder(t *testing.T) {
	cases := []struct {
		bn   int64
		want time.Duration
	}{
		{0, 0},
		{1, 0},
		{bootstrapSecretBruteforceLimit / 4, 0}, // at the boundary: not yet elevated
		{bootstrapSecretBruteforceLimit/4 + 1, 200 * time.Millisecond},
		{bootstrapSecretBruteforceLimit / 2, 200 * time.Millisecond}, // at the boundary
		{bootstrapSecretBruteforceLimit/2 + 1, 1 * time.Second},
		{bootstrapSecretBruteforceLimit * 3 / 4, 1 * time.Second}, // at the boundary
		{bootstrapSecretBruteforceLimit*3/4 + 1, 3 * time.Second},
		{bootstrapSecretBruteforceLimit + 1, 3 * time.Second}, // past the alert threshold: capped, not unbounded
		{1000, 3 * time.Second},                               // still capped for a sustained attacker
	}
	for _, c := range cases {
		if got := bootstrapSecretDelay(c.bn); got != c.want {
			t.Errorf("bootstrapSecretDelay(%d) = %v, want %v", c.bn, got, c.want)
		}
	}
}

// TestBootstrapSecretSleep_RespectsContextCancellation verifies the real
// sleep implementation returns as soon as the request context is cancelled,
// rather than always waiting out the full delay — so a client that
// disconnects mid-throttle doesn't hold the goroutine for nothing.
//
// Calls bootstrapSecretRealSleep directly, NOT the bootstrapSecretSleep var —
// TestMain above has already replaced that var with a no-op stub for every
// test in this package by the time this runs, so a call through the var would
// always return instantly regardless of whether real cancellation handling
// works (VULN-904-B: an earlier version of this test did exactly that and
// could never fail no matter how broken the real implementation was).
func TestBootstrapSecretSleep_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	bootstrapSecretRealSleep(ctx, time.Hour) // would hang the test if cancellation were ignored
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bootstrapSecretRealSleep did not return promptly on context cancellation: took %v", elapsed)
	}
}

// TestBootstrapSecretRealSleep_WaitsOutTheFullDelay is the negative-control
// sibling of the cancellation test above: without it, a broken
// bootstrapSecretRealSleep that returned immediately regardless of ctx (e.g.
// an accidentally-inverted select, or a stray early return) would still pass
// the cancellation test — that test only checks the "cancels early" half of
// the contract, never the "otherwise actually waits" half.
func TestBootstrapSecretRealSleep_WaitsOutTheFullDelay(t *testing.T) {
	const d = 30 * time.Millisecond
	start := time.Now()
	bootstrapSecretRealSleep(context.Background(), d)
	if elapsed := time.Since(start); elapsed < d {
		t.Fatalf("bootstrapSecretRealSleep(%v) returned after only %v — did not wait out the delay", d, elapsed)
	}
}

// TestBootstrapSecretThrottle_ExcessCallersWaitNotSkip is the direct
// regression test for VULN-904-A's core claim: once the semaphore is
// saturated, an additional caller WAITS for a slot rather than returning
// immediately as if untouched.
//
// Occupies the semaphore DETERMINISTICALLY by sending on the raw channel
// directly, rather than by racing goroutines through bootstrapSecretThrottle
// and hoping a fixed time.Sleep was long enough for them to win the race
// (VULN-701: an earlier version of this test did exactly that — a 10ms sleep
// to "let them acquire" before starting the timed call — which had a real
// chance of flaking under CI contention or `-race`'s scheduling overhead: if
// the background goroutines hadn't both acquired their slots yet, the timed
// call could win the race for a free slot and return near-instantly,
// producing a false failure that looks like a throttle-bypass regression but
// is really just test-harness timing noise). Sending on a channel we already
// hold both ends of is synchronous and immediate — no scheduler race.
func TestBootstrapSecretThrottle_ExcessCallersWaitNotSkip(t *testing.T) {
	const capacity = 2
	const holdTime = 100 * time.Millisecond

	origSem := bootstrapSecretDelaySemaphore
	origAdmission := bootstrapSecretQueueAdmission
	bootstrapSecretDelaySemaphore = make(chan struct{}, capacity)
	bootstrapSecretQueueAdmission = make(chan struct{}, capacity+1)
	t.Cleanup(func() {
		bootstrapSecretDelaySemaphore = origSem
		bootstrapSecretQueueAdmission = origAdmission
	})

	// Fill every slot directly — guaranteed full before the timed call below
	// ever starts, no race with a background goroutine's scheduling.
	for i := 0; i < capacity; i++ {
		bootstrapSecretDelaySemaphore <- struct{}{}
	}
	// Drain the LOCAL channel, never the package variable. Reading the global
	// here was a cross-test leak: under CI contention this AfterFunc could still
	// be running after the test returned, by which point the variable pointed at
	// the NEXT test's semaphore — so it stole that test's token, handed its
	// throttle call a slot it should never have gotten, and turned a clean
	// assertion failure into a 10-minute timeout (CI, 2026-08-28).
	sem := bootstrapSecretDelaySemaphore
	drained := make(chan struct{})
	release := time.AfterFunc(holdTime, func() {
		defer close(drained)
		for i := 0; i < capacity; i++ {
			<-sem
		}
	})
	// Nothing this test started may outlive it: if the timer already fired,
	// Stop() is a no-op and only the drained signal proves the goroutine is done.
	defer func() {
		if !release.Stop() {
			<-drained
		}
	}()

	start := time.Now()
	bootstrapSecretThrottle(context.Background(), time.Millisecond) // trivial delay once it gets a slot
	waited := time.Since(start)

	// The caller could only have gotten a slot after release() freed one
	// (~holdTime later) — if it had skipped/sailed through instead, `waited`
	// would be near-zero.
	if waited < holdTime/2 {
		t.Fatalf("excess caller returned in %v without waiting for a saturated slot (want >= ~%v) — VULN-904-A: throttle is being bypassed under load",
			waited, holdTime)
	}
}

// TestBootstrapSecretThrottle_MaxQueueWaitBounded is a regression test for
// VULN-905: a caller that can't get a semaphore slot within
// bootstrapSecretMaxQueueWait must give up and proceed unthrottled, rather
// than waiting indefinitely (bounded in the earlier version of this fix only
// by the admin server's own connection timeout — a denial in practice, not a
// bounded delay, for a legitimate operator queued behind a sustained flood).
// Saturates the semaphore for LONGER than bootstrapSecretMaxQueueWait and
// confirms the extra caller returns (gives up) at approximately the queue-
// wait bound, not after the full hold time.
func TestBootstrapSecretThrottle_MaxQueueWaitBounded(t *testing.T) {
	origSem := bootstrapSecretDelaySemaphore
	origAdmission := bootstrapSecretQueueAdmission
	bootstrapSecretDelaySemaphore = make(chan struct{}, 1)
	bootstrapSecretQueueAdmission = make(chan struct{}, 2)
	t.Cleanup(func() {
		bootstrapSecretDelaySemaphore = origSem
		bootstrapSecretQueueAdmission = origAdmission
	})

	// Hold the only slot for far longer than bootstrapSecretMaxQueueWait.
	bootstrapSecretDelaySemaphore <- struct{}{}
	// Non-blocking: on a failing assertion this defer must not deadlock. A
	// blocking receive here is what turned the failure above into a 600s test
	// timeout, which reports as "hung" and buries the actual assertion message.
	defer func() {
		select {
		case <-bootstrapSecretDelaySemaphore:
		default:
		}
	}()

	start := time.Now()
	throttled := bootstrapSecretThrottle(context.Background(), time.Millisecond)
	waited := time.Since(start)

	if throttled {
		t.Fatal("bootstrapSecretThrottle returned true (throttled) despite never getting a slot within the max queue wait")
	}
	// Should give up at ~bootstrapSecretMaxQueueWait, well before the slot
	// would ever free on its own in this test.
	if waited > bootstrapSecretMaxQueueWait+500*time.Millisecond {
		t.Fatalf("bootstrapSecretThrottle waited %v, want ~%v (VULN-905: queue wait must be bounded)",
			waited, bootstrapSecretMaxQueueWait)
	}
	if waited < bootstrapSecretMaxQueueWait-500*time.Millisecond {
		t.Fatalf("bootstrapSecretThrottle gave up after only %v, want ~%v — gave up too early", waited, bootstrapSecretMaxQueueWait)
	}
}

// TestBootstrapSecretThrottle_AdmissionCapped is a regression test for
// VULN-906: once bootstrapSecretQueueAdmission itself is saturated, an
// additional caller must return immediately (unthrottled) rather than piling
// on as one more goroutine/connection queued for a queue slot.
func TestBootstrapSecretThrottle_AdmissionCapped(t *testing.T) {
	origSem := bootstrapSecretDelaySemaphore
	origAdmission := bootstrapSecretQueueAdmission
	bootstrapSecretDelaySemaphore = make(chan struct{}, 1)
	bootstrapSecretQueueAdmission = make(chan struct{}, 1)
	t.Cleanup(func() {
		bootstrapSecretDelaySemaphore = origSem
		bootstrapSecretQueueAdmission = origAdmission
	})

	// Fill both the only delay slot AND the only admission slot.
	bootstrapSecretDelaySemaphore <- struct{}{}
	// Non-blocking: on a failing assertion this defer must not deadlock. A
	// blocking receive here is what turned the failure above into a 600s test
	// timeout, which reports as "hung" and buries the actual assertion message.
	defer func() {
		select {
		case <-bootstrapSecretDelaySemaphore:
		default:
		}
	}()
	bootstrapSecretQueueAdmission <- struct{}{}
	defer func() { <-bootstrapSecretQueueAdmission }()

	start := time.Now()
	throttled := bootstrapSecretThrottle(context.Background(), time.Millisecond)
	waited := time.Since(start)

	if throttled {
		t.Fatal("bootstrapSecretThrottle returned true despite admission being fully saturated")
	}
	if waited > 50*time.Millisecond {
		t.Fatalf("bootstrapSecretThrottle took %v to give up on a saturated admission queue, want near-instant", waited)
	}
}

// TestLogin_BootstrapSecret_ThrottledMetric is a regression test for
// VULN-904: once the cross-IP failure count for the bootstrap-secret path
// climbs past the ladder's first rung, the throttle metric must fire (proving
// the delay path was actually taken, even though TestMain stubs out the
// real sleep for test speed).
func TestLogin_BootstrapSecret_ThrottledMetric(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	failFromIP := func(i int) int {
		b, _ := json.Marshal(map[string]string{"secret": "wrong"})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
		r.RemoteAddr = "198.51.100." + strconv.Itoa(i) + ":1111"
		rec := httptest.NewRecorder()
		h.login(rec, r)
		return rec.Code
	}

	// One past the first rung (bootstrapSecretBruteforceLimit/4 = 10).
	for i := 1; i <= bootstrapSecretBruteforceLimit/4+1; i++ {
		if code := failFromIP(i); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, code)
		}
	}

	metrics, err := h.store.GetMetrics(context.Background())
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if metrics["admin_bootstrap_secret_throttled"] < 1 {
		t.Fatalf("admin_bootstrap_secret_throttled metric = %d, want >= 1 (VULN-904: throttle should have engaged)",
			metrics["admin_bootstrap_secret_throttled"])
	}
}

// TestLogin_BootstrapSecret_SuccessRefundsTelemetryCounter is a regression
// test for VULN-901: a successful bootstrap-secret login must refund the
// telemetry counter (DecrRate), not just avoid being blocked by it. Without
// the refund, every legitimate CI/operator login silently consumes budget
// identical to an attacker's failure, so a handful of ordinary successful
// logins interleaved with a handful of typos would cross the alert threshold
// from mostly-legitimate traffic. This drives the counter to exactly
// bootstrapSecretBruteforceLimit via successes (which must never count
// against the budget if refunded correctly), then proves one more real
// failure does NOT yet cross the threshold — which it would if any of the
// preceding successes had leaked into the count.
func TestLogin_BootstrapSecret_SuccessRefundsTelemetryCounter(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	succeed := func(i int) int {
		b, _ := json.Marshal(map[string]string{"secret": h.cfg.AdminSecret})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
		r.RemoteAddr = "198.51.100." + strconv.Itoa(i) + ":1111"
		rec := httptest.NewRecorder()
		h.login(rec, r)
		return rec.Code
	}

	for i := 1; i <= bootstrapSecretBruteforceLimit; i++ {
		if code := succeed(i); code != http.StatusOK {
			t.Fatalf("successful login %d: got %d, want 200", i, code)
		}
	}

	n, err := h.store.GetRate(context.Background(), bootstrapSecretLoginKey)
	if err != nil {
		t.Fatalf("GetRate: %v", err)
	}
	if n != 0 {
		t.Fatalf("bootstrap-secret telemetry counter after %d successful logins = %d, want 0 (VULN-901: successes must be refunded, not counted as failures)",
			bootstrapSecretBruteforceLimit, n)
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
