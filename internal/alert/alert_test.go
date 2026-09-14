package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"api-gateway/internal/logger"
	"api-gateway/internal/safefetch"
)

func testLogger() *logger.Logger { return logger.New("error") }

// loopbackDelivery points an Engine at a test server.
//
// The production client refuses to connect to an internal address — that is the
// whole point of safefetch.Client, and httptest listens on loopback — so a test
// that exercises DELIVERY has to dial loopback deliberately. The redirect policy
// is left in place, because several tests below are about redirects.
//
// Nothing in production builds a client this way: the only constructor is
// safefetch.Client, and it has no opt-out.
func loopbackDelivery(e *Engine) *Engine {
	e.client = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return safefetch.Redirect("alert_webhook_test", req, via)
		},
	}
	return e
}

// captureServer records the last POSTed body and counts delivered alerts.
func captureServer(t *testing.T, last *atomic.Value, count *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		last.Store(body)
		atomic.AddInt32(count, 1)
		w.WriteHeader(http.StatusOK)
	}))
}

func TestFire_DeliversAboveThreshold(t *testing.T) {
	var last atomic.Value
	var count int32
	srv := captureServer(t, &last, &count)
	defer srv.Close()

	e := loopbackDelivery(NewWithConfig(srv.URL, "generic", SeverityWarning, testLogger()))
	e.Fire(context.Background(), SeverityCritical, "BOLA detected", "consumer x")

	if atomic.LoadInt32(&count) != 1 {
		t.Fatalf("expected 1 delivery, got %d", count)
	}
	var payload map[string]string
	if err := json.Unmarshal(last.Load().([]byte), &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload["source"] != "aegis" || payload["title"] != "BOLA detected" {
		t.Fatalf("unexpected generic payload: %v", payload)
	}
}

func TestFire_SuppressedBelowThreshold(t *testing.T) {
	var last atomic.Value
	var count int32
	srv := captureServer(t, &last, &count)
	defer srv.Close()

	e := loopbackDelivery(NewWithConfig(srv.URL, "generic", SeverityCritical, testLogger()))
	e.Fire(context.Background(), SeverityWarning, "minor", "noise")

	if atomic.LoadInt32(&count) != 0 {
		t.Fatalf("expected suppression, got %d deliveries", count)
	}
}

func TestFire_SlackFormat(t *testing.T) {
	var last atomic.Value
	var count int32
	srv := captureServer(t, &last, &count)
	defer srv.Close()

	e := loopbackDelivery(NewWithConfig(srv.URL, "slack", SeverityInfo, testLogger()))
	e.Fire(context.Background(), SeverityCritical, "BFLA", "admin path")

	var payload map[string]string
	if err := json.Unmarshal(last.Load().([]byte), &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if _, ok := payload["text"]; !ok {
		t.Fatalf("slack payload missing text field: %v", payload)
	}
	if want := "CRITICAL — BFLA"; payload["text"][:len(want)] != want {
		t.Fatalf("slack text = %q, want prefix %q", payload["text"], want)
	}
}

func TestFire_NoWebhookNoPanic(t *testing.T) {
	e := NewWithConfig("", "generic", SeverityInfo, testLogger())
	// Must not panic or block when no webhook is configured.
	e.Fire(context.Background(), SeverityCritical, "t", "b")
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SeverityInfo) >= severityRank(SeverityWarning) {
		t.Fatal("info should rank below warning")
	}
	if severityRank(SeverityWarning) >= severityRank(SeverityCritical) {
		t.Fatal("warning should rank below critical")
	}
	if severityRank("bogus") != severityRank(SeverityWarning) {
		t.Fatal("unknown severity should rank as warning")
	}
}

// A webhook that redirects must not carry the alert off the pinned https
// destination. config.Validate pins the scheme an operator wrote; the default
// client would follow a 302 to http://, where the alert body — the detection,
// the endpoint, often the consumer — travels in clear, or to an internal
// address, which makes every fired alert a blind SSRF from inside the gateway.
//
// The assertion is on the REDIRECT TARGET, not on the redirector: the
// redirector is hit exactly once whether or not the hop is followed, so
// counting its calls passes on a client with no policy at all.
func TestFire_DoesNotFollowRedirectOffThePin(t *testing.T) {
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// httptest serves plaintext on a loopback address, so this one target is
	// refused twice over: the scheme is http and the host is private. Both are
	// hops an operator's https pin is supposed to survive.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	e := loopbackDelivery(NewWithConfig(redirector.URL, "generic", SeverityWarning, testLogger()))
	e.Fire(context.Background(), SeverityCritical, "bola detected",
		"consumer sub=alice enumerated 300 objects")

	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("the alert body reached the redirect target %d times; "+
			"the https pin did not survive a 302", got)
	}
}
