package incident

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeStore records merges instead of writing them.
type fakeStore struct {
	mu     sync.Mutex
	merges []Delta
	window time.Duration
	err    error
}

func (f *fakeStore) Merge(_ context.Context, d Delta, window time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.merges = append(f.merges, d)
	f.window = window
	return f.err
}

func (f *fakeStore) all() []Delta {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Delta, len(f.merges))
	copy(out, f.merges)
	return out
}

type nopLog struct{}

func (nopLog) Error(string, ...map[string]any) {}

// The exclusions are the point of ClassOf. An incident list that fills with
// rate-limit rejections teaches the operator to stop looking, and the incident
// that needed a 24-hour early warning is in there somewhere.
func TestClassOf(t *testing.T) {
	opens := map[string]string{
		"bola_object_ownership":  "bola",
		"bfla_privileged_access": "bfla",
		"waf_blocked":            "waf",
		"behavior_high_risk":     "behavior",
		"threat_feed_blocked":    "threat",
	}
	for reason, want := range opens {
		if got := ClassOf(reason); got != want {
			t.Errorf("%s → %q, want %q", reason, got, want)
		}
	}
	// Controls working as designed, thousands of times a day. Not incidents.
	for _, reason := range []string{
		"rate_limit_exceeded", "dlp_redacted", "ip_blacklisted",
		"ip_blocked_dynamic", "bot_ja3_blocked", "", "requests_passed_waf",
	} {
		if got := ClassOf(reason); got != "" {
			t.Errorf("%s opened an incident of class %q — routine control activity must not", reason, got)
		}
	}
}

func TestCorrelator_GroupsEventsIntoOneIncident(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	defer func() { _ = c.Close() }()

	for i := 0; i < 20; i++ {
		c.Observe(Event{
			Tenant: "acme", Reason: "bola_object_ownership", Consumer: "jwt:alice",
			IP: "1.2.3.4", Endpoint: "GET /orders/{id}", At: t0.Add(time.Duration(i) * time.Second),
		})
	}
	c.Flush()

	got := fs.all()
	if len(got) != 1 {
		t.Fatalf("%d merges, want 1 — twenty events of one campaign must not be twenty incidents", len(got))
	}
	d := got[0]
	if d.Count != 20 {
		t.Errorf("count = %d, want 20", d.Count)
	}
	if !d.First.Equal(t0) || !d.Last.Equal(t0.Add(19*time.Second)) {
		t.Errorf("span = %s..%s, want the first and last event", d.First, d.Last)
	}
	if d.Subject != "jwt:alice" {
		t.Errorf("subject = %q, want the consumer identity", d.Subject)
	}
	if len(d.Endpoints) != 1 || d.Endpoints[0] != "GET /orders/{id}" {
		t.Errorf("endpoints = %v", d.Endpoints)
	}
}

// A verified consumer beats a source address. Correlating on the address splits
// one campaign into hundreds of incidents the moment the attacker rotates it.
func TestCorrelator_PrefersTheConsumerOverTheAddress(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	defer func() { _ = c.Close() }()

	for i, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		c.Observe(Event{Tenant: "acme", Reason: "bola_x", Consumer: "jwt:alice", IP: ip,
			Endpoint: "GET /orders/{id}", At: t0.Add(time.Duration(i) * time.Second)})
	}
	c.Flush()

	got := fs.all()
	if len(got) != 1 {
		t.Fatalf("%d merges, want 1 — rotating the source address split the campaign", len(got))
	}
	if len(got[0].Sources) != 3 {
		t.Errorf("sources = %v, want all three addresses recorded", got[0].Sources)
	}
}

// Without a consumer there is nothing else to correlate on.
func TestCorrelator_FallsBackToTheAddress(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	defer func() { _ = c.Close() }()

	c.Observe(Event{Tenant: "acme", Reason: "waf_blocked", IP: "9.9.9.9", At: t0})
	c.Observe(Event{Tenant: "acme", Reason: "waf_blocked", IP: "8.8.8.8", At: t0})
	c.Flush()

	if got := fs.all(); len(got) != 2 {
		t.Fatalf("%d merges, want 2 — different addresses are different incidents when there is no identity", len(got))
	}
}

func TestCorrelator_SeparatesTenantsAndClasses(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	defer func() { _ = c.Close() }()

	c.Observe(Event{Tenant: "a", Reason: "bola_x", Consumer: "u1", At: t0})
	c.Observe(Event{Tenant: "b", Reason: "bola_x", Consumer: "u1", At: t0})
	c.Observe(Event{Tenant: "a", Reason: "waf_blocked", Consumer: "u1", At: t0})
	c.Flush()

	if got := fs.all(); len(got) != 3 {
		t.Fatalf("%d merges, want 3 (two tenants, two classes)", len(got))
	}
}

// Routine control activity must be discarded before it costs a buffer slot,
// never merely filtered later.
func TestCorrelator_DiscardsNonIncidentEvents(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	defer func() { _ = c.Close() }()

	for i := 0; i < 100; i++ {
		c.Observe(Event{Tenant: "acme", Reason: "rate_limit_exceeded", IP: "1.2.3.4", At: t0})
	}
	c.Flush()

	if got := fs.all(); len(got) != 0 {
		t.Fatalf("%d merges, want 0: %+v", len(got), got)
	}
}

// Observe runs on the request path. A store that has stopped answering, or a
// flood larger than the buffer, must never turn into latency for the caller.
func TestCorrelator_ObserveNeverBlocks(t *testing.T) {
	// Built without a worker so NOTHING drains the buffer. Running the real
	// correlator here proves nothing: the worker consumes events as fast as a
	// test can produce them, so the buffer never fills and the overflow branch
	// — the only branch that can block — is never taken. This is the shape that
	// actually exercises it.
	c := &Correlator{
		ch:       make(chan Event, 4),
		quit:     make(chan struct{}),
		flushReq: make(chan chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ { // far past the buffer
			c.Observe(Event{Tenant: "acme", Reason: "bola_x", IP: "1.2.3.4", At: t0})
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Observe blocked once the buffer was full — a flood is exactly when that happens, " +
			"and it would turn the incident recorder into latency on the attacked request")
	}
	if len(c.ch) != cap(c.ch) {
		t.Errorf("buffer holds %d of %d; the test did not actually fill it", len(c.ch), cap(c.ch))
	}
}

// Close must persist what it is still holding; an incident lost at shutdown is
// an incident that was never reported.
func TestCorrelator_CloseFlushes(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	c.Observe(Event{Tenant: "acme", Reason: "bola_x", Consumer: "u1", At: t0})
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := fs.all(); len(got) != 1 {
		t.Fatalf("%d merges after Close, want 1 — the pending incident was dropped", len(got))
	}
}

// An event with no timestamp still has to land somewhere sensible, or it sorts
// to the zero time and the incident claims to have started in year 1.
func TestCorrelator_StampsAnUndatedEvent(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	before := time.Now().UTC().Add(-time.Second)
	c.Observe(Event{Tenant: "acme", Reason: "bola_x", Consumer: "u1"})
	_ = c.Close()

	got := fs.all()
	if len(got) != 1 {
		t.Fatalf("%d merges, want 1", len(got))
	}
	if got[0].First.Before(before) {
		t.Errorf("first = %s, want roughly now", got[0].First)
	}
}

// A nil correlator is what a deployment without PostgreSQL has. Every call must
// be safe, because the alternative is a nil dereference on the request path.
func TestCorrelator_NilIsSafe(t *testing.T) {
	var c *Correlator
	c.Observe(Event{Tenant: "acme", Reason: "bola_x"})
	c.Flush()
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil: %v", err)
	}
}

// The caps are not cosmetic: these lists grow from attacker-supplied values.
// The ORDER is the security-relevant part — keeping the lexicographically
// smallest let an attacker evict real evidence by sending values that sort
// before it.
func TestBoundedUnique_KeepsFirstSeenAndReportsTruncation(t *testing.T) {
	got, dropped := boundedUnique([]string{"b", "a", "b", "", "c"}, 10)
	if len(got) != 3 || got[0] != "b" || got[1] != "a" || got[2] != "c" {
		t.Errorf("got %v, want first-seen order [b a c]", got)
	}
	if dropped {
		t.Error("nothing was dropped but truncation was reported")
	}

	// The eviction attack: the real target is seen first, then fifty decoys
	// that would all sort before it.
	in := []string{"GET /admin/keys"}
	for i := 0; i < 60; i++ {
		in = append(in, fmt.Sprintf("GET /AAA%02d", i))
	}
	kept, dropped := boundedUnique(in, 50)
	if !dropped {
		t.Error("values were dropped but truncation was not reported")
	}
	if len(kept) != 50 {
		t.Fatalf("kept %d, want the cap of 50", len(kept))
	}
	if kept[0] != "GET /admin/keys" {
		t.Fatalf("the first-seen value was evicted by later ones: %v", kept[:3])
	}
}

// The per-incident lists were capped; the MAP of incident streams was not, and
// its key includes the source address. An attacker rotating addresses grew it
// without limit and then made the worker walk every entry serially against
// PostgreSQL — incident recording degraded to nothing during precisely the
// distributed attack it exists to record.
func TestCorrelator_BoundsTheNumberOfStreams(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})

	// One address per event, far past the cap.
	for i := 0; i < maxPendingKeys+500; i++ {
		c.Observe(Event{Tenant: "acme", Reason: "waf_blocked",
			IP: fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), At: t0})
	}
	_ = c.Close()

	if got := len(fs.all()); got > maxPendingKeys {
		t.Fatalf("%d streams written, want at most the cap of %d", got, maxPendingKeys)
	}
}

// An already-tracked stream must keep accumulating even while new ones are
// being refused — otherwise a flood of new addresses starves the incident that
// is actually being recorded.
func TestCorrelator_CapRefusesNewStreamsNotExistingOnes(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})

	c.Observe(Event{Tenant: "acme", Reason: "bola_x", Consumer: "jwt:victim", At: t0})
	for i := 0; i < maxPendingKeys+100; i++ {
		c.Observe(Event{Tenant: "acme", Reason: "waf_blocked",
			IP: fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), At: t0})
	}
	c.Observe(Event{Tenant: "acme", Reason: "bola_x", Consumer: "jwt:victim", At: t0.Add(time.Second)})
	_ = c.Close()

	for _, d := range fs.all() {
		if d.Subject == "jwt:victim" {
			if d.Count != 2 {
				t.Errorf("the tracked stream recorded %d events, want 2 — a flood of new "+
					"streams starved an incident already being recorded", d.Count)
			}
			return
		}
	}
	t.Fatal("the tracked stream was not written at all")
}

// Close is the shutdown path that flushes evidence. A panic there loses the
// final batch.
func TestCorrelator_CloseIsIdempotent(t *testing.T) {
	c := New(&fakeStore{}, nopLog{})
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil { // must not panic on a closed channel
		t.Fatalf("second Close: %v", err)
	}
}
