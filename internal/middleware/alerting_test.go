package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/tenant"
)

// recordingEngine captures what would have been delivered.
type recordingEngine struct {
	mu    sync.Mutex
	fired []string
	seen  []string // tenant read from the context each Fire received
	block chan struct{}
}

// Fire mirrors what the real engine does with the context: it hands it to
// http.NewRequestWithContext, so a cancelled context means the POST never
// leaves. Honouring that here is what lets a test tell a detached context from
// one that merely looks detached.
func (e *recordingEngine) Fire(ctx context.Context, level, title, body string) {
	if e.block != nil {
		<-e.block
	}
	if ctx.Err() != nil {
		return // the delivery would have failed before reaching the webhook
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fired = append(e.fired, level+"|"+title)
	e.seen = append(e.seen, tenant.From(ctx))
}

func (e *recordingEngine) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.fired)
}

// waitFor polls until cond holds or the deadline passes — delivery is
// asynchronous by design, so assertions cannot read the result immediately.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// countingRate implements RateLimiter with a real per-key counter, so the dedup
// gate is exercised rather than stubbed.
type countingRate struct {
	mu   sync.Mutex
	n    map[string]int64
	fail bool
}

func (r *countingRate) IncrRate(_ context.Context, key string, _ time.Duration) (int64, error) {
	if r.fail {
		return 0, errors.New("store down")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == nil {
		r.n = map[string]int64{}
	}
	r.n[key]++
	return r.n[key], nil
}

// An attacker controls how often the events behind these alerts fire. Without a
// gate one loop becomes thousands of webhook POSTs, which floods on-call, gets
// the gateway throttled by the receiving service, and buries the first alert —
// the only one that mattered.
func TestAlerter_DeduplicatesPerKey(t *testing.T) {
	eng := &recordingEngine{}
	a := NewAlerter(eng, &countingRate{}, fakeLogger{})

	for i := 0; i < 25; i++ {
		a.Notify(context.Background(), "warning", "bola_enumeration:alice", "t", "b")
	}
	waitFor(t, func() bool { return eng.count() >= 1 }, "no alert was delivered at all")
	time.Sleep(100 * time.Millisecond) // let any duplicates arrive before asserting

	if n := eng.count(); n != 1 {
		t.Fatalf("%d alerts delivered for one key; a caller in a loop pages on-call once per request", n)
	}

	// A different subject is a different incident and must still get through.
	a.Notify(context.Background(), "warning", "bola_enumeration:mallory", "t", "b")
	waitFor(t, func() bool { return eng.count() == 2 }, "a distinct alert key was suppressed by another key's dedup")
}

// Carrying the request context would let an attacker cancel the alert about
// their own attack simply by aborting the connection: the POST would be
// cancelled before it left the process.
func TestAlerter_SurvivesRequestCancellation(t *testing.T) {
	eng := &recordingEngine{}
	a := NewAlerter(eng, &countingRate{}, fakeLogger{})

	// Cancel BEFORE notifying, so the outcome cannot depend on whether the
	// delivery goroutine happened to win a race against the disconnect.
	ctx, cancel := context.WithCancel(tenant.With(context.Background(), "acme"))
	cancel() // the caller has already hung up
	a.Notify(ctx, "critical", "bola_object_ownership:alice", "t", "b")

	waitFor(t, func() bool { return eng.count() == 1 },
		"the alert died with the request context: an attacker suppresses the alert about their own attack by disconnecting")

	eng.mu.Lock()
	gotTenant := eng.seen[0]
	eng.mu.Unlock()
	if gotTenant != "acme" {
		t.Errorf("tenant = %q, want acme — detaching the context must not lose the tenant scope", gotTenant)
	}
}

// Notify must return before delivery completes, or a slow webhook adds its
// timeout to every request that triggers an alert.
func TestAlerter_DoesNotBlockTheCaller(t *testing.T) {
	eng := &recordingEngine{block: make(chan struct{})}
	a := NewAlerter(eng, &countingRate{}, fakeLogger{})

	done := make(chan struct{})
	go func() {
		a.Notify(context.Background(), "warning", "k", "t", "b")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Notify blocked on delivery; a hung webhook would stall the request path")
	}
	close(eng.block)
}

// On a store outage the duplicate count is unknown. A duplicate page is a
// nuisance; a missed one is the failure this path exists to prevent.
func TestAlerter_DeliversWhenTheDedupStoreIsDown(t *testing.T) {
	eng := &recordingEngine{}
	a := NewAlerter(eng, &countingRate{fail: true}, fakeLogger{})
	a.Notify(context.Background(), "warning", "k", "t", "b")
	waitFor(t, func() bool { return eng.count() == 1 }, "a store outage silenced alerting entirely")
}

// A nil engine (no alerting configured) must be inert, not a panic.
func TestAlerter_NilEngineIsSafe(t *testing.T) {
	NewAlerter(nil, &countingRate{}, fakeLogger{}).Notify(context.Background(), "warning", "k", "t", "b")
	var nilAlerter *Alerter
	nilAlerter.Notify(context.Background(), "warning", "k", "t", "b")
}

// The point of the whole change: a BOLA detection must reach the notification
// path. Before this, alert.Fire had no callers anywhere — the engine was built,
// configured, validated and documented as delivering webhooks, while nothing
// ever invoked it. An operator pointing it at PagerDuty would never be paged,
// and silence was indistinguishable from no attacks.
func TestAbuseDetection_FiresAnAlertOnEnumeration(t *testing.T) {
	eng := &recordingEngine{}
	st := &fakeStore{trackObject: func() (int64, error) { return 99, nil }}
	al := NewAlerter(eng, &countingRate{}, fakeLogger{})

	h := AbuseDetection(config.AbuseConfig{Enabled: true, EnumThreshold: 5}, "", fakeLogger{}, st, al)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	r := httptest.NewRequest(http.MethodGet, "/orders/4242", nil)
	r.Header.Set("X-Gateway-Subject", "alice")
	h.ServeHTTP(httptest.NewRecorder(), r)

	waitFor(t, func() bool { return eng.count() == 1 },
		"a BOLA enumeration detection produced no alert: the notification path is not wired")

	eng.mu.Lock()
	got := eng.fired[0]
	eng.mu.Unlock()
	if !strings.Contains(got, "bola_enumeration") {
		t.Errorf("alert = %q, want it to name the detection", got)
	}
}

// Observe mode records rather than blocks, so the notification path — which is
// recording — must stay live. Silencing it there would repeat the WAF's
// detection-mode silence that this session already had to fix.
func TestAbuseDetection_AlertsInObserveMode(t *testing.T) {
	eng := &recordingEngine{}
	st := &fakeStore{trackObject: func() (int64, error) { return 99, nil }}
	al := NewAlerter(eng, &countingRate{}, fakeLogger{})

	// BlockMode false is what ApplyObserveMode coerces abuse detection to.
	h := AbuseDetection(config.AbuseConfig{Enabled: true, EnumThreshold: 5, BlockMode: false}, "", fakeLogger{}, st, al)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	r := httptest.NewRequest(http.MethodGet, "/orders/4242", nil)
	r.Header.Set("X-Gateway-Subject", "alice")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("observe mode must not block: got %d", rec.Code)
	}
	waitFor(t, func() bool { return eng.count() == 1 }, "no alert in observe mode, where recording is the entire product")
}
