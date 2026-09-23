package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"api-gateway/internal/logger"
)

// recorder is a stand-in collector that captures what was actually sent.
type recorder struct {
	mu      sync.Mutex
	bodies  []map[string]any
	headers []http.Header
	status  int
	delay   time.Duration
	hits    atomic.Int64
}

func (r *recorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		if r.delay > 0 {
			time.Sleep(r.delay)
		}
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		r.mu.Lock()
		r.bodies = append(r.bodies, body)
		r.headers = append(r.headers, req.Header.Clone())
		r.mu.Unlock()
		if r.status != 0 {
			w.WriteHeader(r.status)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (r *recorder) last() (map[string]any, http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return nil, nil
	}
	return r.bodies[len(r.bodies)-1], r.headers[len(r.headers)-1]
}

// loopbackSink points a sink at a test server.
//
// httptest listens on 127.0.0.1, and BOTH production clients refuse loopback —
// safefetch.Client because no configured destination may be internal, and
// safefetch.InternalClient because a collector on loopback would be the gateway
// posting alerts to its own admin API. That refusal is the correct production
// behaviour and it is asserted in TestSink_RefusesLoopbackEvenWhenPrivateIsAllowed
// below; a test that exercises DELIVERY has to dial loopback deliberately.
//
// Nothing in production builds a client this way: NewSink is the only
// constructor, and it has no opt-out.
func loopbackSink(s Sink) Sink {
	s.client = &http.Client{Timeout: 10 * time.Second}
	return s
}

// engineWith builds an engine with no webhook, so a test observes sinks alone.
func engineWith(sinks ...Sink) *Engine {
	for i := range sinks {
		sinks[i] = loopbackSink(sinks[i])
	}
	return NewWithConfig("", "generic", SeverityInfo, logger.New("error")).WithSinks(sinks)
}

func TestSink_SplunkEnvelopeIsWhatHECAccepts(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	e := engineWith(NewSink(SinkSplunkHEC, srv.URL, "tok-123", "aegis", SeverityInfo))
	e.Fire(context.Background(), SeverityCritical, "BOLA confirmed", "jwt:alice read order 42")

	body, headers := rec.last()
	if body == nil {
		t.Fatal("the collector received nothing")
	}
	if got := headers.Get("Authorization"); got != "Splunk tok-123" {
		t.Errorf("Authorization = %q, want %q", got, "Splunk tok-123")
	}
	if body["index"] != "aegis" {
		t.Errorf("index = %v, want aegis", body["index"])
	}
	// The one detail HEC is strict about: `time` must be a number of seconds.
	// A string here is rejected at the collector, and a rejected batch is
	// dropped there — the failure hardest to see from this side.
	if _, ok := body["time"].(float64); !ok {
		t.Errorf("time = %#v (%T), want a numeric epoch — HEC rejects a string",
			body["time"], body["time"])
	}
	event, ok := body["event"].(map[string]any)
	if !ok {
		t.Fatalf("event = %#v, want an object", body["event"])
	}
	if event["severity"] != SeverityCritical || event["title"] != "BOLA confirmed" {
		t.Errorf("event lost the alert: %#v", event)
	}
}

func TestSink_ElasticUsesCommonSchemaFields(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	e := engineWith(NewSink(SinkElastic, srv.URL, "key-abc", "", SeverityInfo))
	e.Fire(context.Background(), SeverityWarning, "rate limit tripped", "1.2.3.4")

	body, headers := rec.last()
	if body == nil {
		t.Fatal("the collector received nothing")
	}
	if got := headers.Get("Authorization"); got != "ApiKey key-abc" {
		t.Errorf("Authorization = %q, want %q", got, "ApiKey key-abc")
	}
	// ECS names, so the events land in dashboards that already exist. A
	// document needing its own mapping is a document nobody queries.
	for _, field := range []string{"@timestamp", "event.kind", "event.dataset", "log.level", "message"} {
		if _, ok := body[field]; !ok {
			t.Errorf("missing ECS field %q: %#v", field, body)
		}
	}
	if body["message"] != "rate limit tripped" {
		t.Errorf("message = %v", body["message"])
	}
}

// An Elastic deployment with security disabled has no API key. Sending an empty
// credential is not the same as sending none: some proxies read `ApiKey ` as a
// malformed credential and refuse the request.
func TestSink_ElasticOmitsTheHeaderWhenThereIsNoKey(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	e := engineWith(NewSink(SinkElastic, srv.URL, "", "", SeverityInfo))
	e.Fire(context.Background(), SeverityCritical, "t", "b")

	_, headers := rec.last()
	if _, present := headers["Authorization"]; present {
		t.Errorf("Authorization header present with no key: %q", headers.Get("Authorization"))
	}
}

// Each destination gates itself. The case that matters is a SIEM wanting
// everything while on-call wants only criticals — if one threshold governed
// both, one of the two would be wrong in every deployment.
func TestSink_EachDestinationGatesItself(t *testing.T) {
	loud, quiet := &recorder{}, &recorder{}
	loudSrv, quietSrv := httptest.NewServer(loud.handler()), httptest.NewServer(quiet.handler())
	defer loudSrv.Close()
	defer quietSrv.Close()

	e := engineWith(
		NewSink(SinkElastic, loudSrv.URL, "", "", SeverityInfo),
		NewSink(SinkElastic, quietSrv.URL, "", "", SeverityCritical),
	)
	e.Fire(context.Background(), SeverityWarning, "warning-level event", "")

	if loud.hits.Load() != 1 {
		t.Errorf("the info-threshold sink got %d events, want 1", loud.hits.Load())
	}
	if quiet.hits.Load() != 0 {
		t.Errorf("the critical-threshold sink got %d events, want 0", quiet.hits.Load())
	}
}

// One collector being down must not cost the others their delivery. Sequential
// fan-out would spend the shared deadline on the first dead sink and never
// reach the rest: an outage in a system nobody watches would silently disable
// the one somebody does.
func TestSink_OneFailingDestinationDoesNotStarveTheOthers(t *testing.T) {
	healthy := &recorder{}
	healthySrv := httptest.NewServer(healthy.handler())
	defer healthySrv.Close()

	// The delay must EXCEED the deadline below, or the test proves nothing: at
	// 300ms against a 400ms budget, sequential delivery still had 100ms left for
	// the healthy sink and passed. Found by mutation — making fanOut sequential
	// left this test green. The dead collector now consumes the entire budget,
	// which is what a real one that has stopped answering does.
	broken := &recorder{status: http.StatusInternalServerError, delay: 2 * time.Second}
	brokenSrv := httptest.NewServer(broken.handler())
	defer brokenSrv.Close()

	e := engineWith(
		NewSink(SinkElastic, brokenSrv.URL, "", "", SeverityInfo),
		NewSink(SinkElastic, healthySrv.URL, "", "", SeverityInfo),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	e.Fire(ctx, SeverityCritical, "t", "b")

	if healthy.hits.Load() != 1 {
		t.Fatalf("the healthy collector got %d events, want 1 — a slow sink ahead of "+
			"it consumed the deadline", healthy.hits.Load())
	}
}

// A deployment that ships to a SIEM and pages nobody is ordinary. Returning
// early on "no webhook configured" would have disabled it silently.
func TestSink_DeliveredWithNoWebhookConfigured(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	e := engineWith(NewSink(SinkElastic, srv.URL, "", "", SeverityInfo))
	if e.webhookURL != "" {
		t.Fatal("this test is meaningless with a webhook configured")
	}
	e.Fire(context.Background(), SeverityCritical, "t", "b")

	if rec.hits.Load() != 1 {
		t.Errorf("SIEM got %d events with no webhook configured, want 1", rec.hits.Load())
	}
}

// The engine's own threshold still governs: an alert suppressed as noise must
// not reach the SIEM by a side door.
func TestSink_EngineThresholdStillSuppresses(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	e := NewWithConfig("", "generic", SeverityCritical, logger.New("error")).
		WithSinks([]Sink{NewSink(SinkElastic, srv.URL, "", "", SeverityInfo)})
	e.Fire(context.Background(), SeverityInfo, "noise", "")

	if rec.hits.Load() != 0 {
		t.Errorf("a suppressed alert reached the SIEM anyway (%d events)", rec.hits.Load())
	}
}

func TestSink_UnknownTypeIsRefusedRatherThanSentNowhere(t *testing.T) {
	if ValidSinkType("splunk_hec") != true || ValidSinkType("elastic") != true {
		t.Error("a supported type was rejected")
	}
	if ValidSinkType("syslog") {
		t.Error("an unsupported type was accepted; it would be configured and deliver nothing")
	}

	s := NewSink("syslog", "https://example.invalid", "", "", SeverityInfo)
	if _, err := s.encode(SeverityCritical, "t", "b", time.Now()); err == nil {
		t.Error("encoding for an unknown type returned no error")
	}
}

// The relaxation for internal destinations must stop well short of "anything
// goes". These are the addresses a sink may never reach however it is
// configured, and the metadata service is the one that matters: it is the
// highest-value SSRF target in any cloud, and "the operator asked for internal"
// must not become a way to reach it.
func TestSink_RefusesLoopbackEvenWhenPrivateIsAllowed(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	// The real constructor, with the relaxation switched on — no test client.
	s := NewSink(SinkElastic, srv.URL, "", "", SeverityInfo, NewSinkOptions{AllowPrivate: true})
	err := s.deliver(context.Background(), SeverityCritical, "t", "b", time.Now())
	if err == nil {
		t.Fatal("a sink allowed to reach private addresses connected to loopback")
	}
	if rec.hits.Load() != 0 {
		t.Errorf("the request reached the server anyway (%d hits)", rec.hits.Load())
	}
}

// And the default stays the strict policy: a sink that did not ask for the
// relaxation must behave exactly like the webhook.
func TestSink_PrivateIsRefusedByDefault(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	s := NewSink(SinkElastic, srv.URL, "", "", SeverityInfo)
	if err := s.deliver(context.Background(), SeverityCritical, "t", "b", time.Now()); err == nil {
		t.Fatal("the default sink connected to an internal address")
	}
}
