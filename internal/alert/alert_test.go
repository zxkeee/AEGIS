package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"api-gateway/internal/logger"
)

func testLogger() *logger.Logger { return logger.New("error") }

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

	e := NewWithConfig(srv.URL, "generic", SeverityWarning, testLogger())
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

	e := NewWithConfig(srv.URL, "generic", SeverityCritical, testLogger())
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

	e := NewWithConfig(srv.URL, "slack", SeverityInfo, testLogger())
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
