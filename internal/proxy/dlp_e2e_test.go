package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
)

// nopMetrics is a no-op MetricsSink for the DLP end-to-end test.
type nopMetrics struct{}

func (nopMetrics) IncrMetric(context.Context, string) {}

// TestDLP_EndToEnd_ChunkedBackendIsRedacted is the real-proxy proof of the P0
// DLP fix. It wires the ACTUAL httputil.ReverseProxy behind the ACTUAL DLP
// middleware and puts a backend behind it that flushes mid-response — so the
// upstream reply carries Content-Length: -1 (chunked). Go's reverse proxy
// flushes such a body to the client immediately; before the fix that emitted
// the bytes before classify.Redact ran, leaking PII on every chunked response.
//
// Unlike the unit test (which simulates Flush on a recorder), this drives a live
// HTTP server end-to-end, exercising the maxLatencyWriter → dlpWriter.Flush path
// that actually triggered the bug.
func TestDLP_EndToEnd_ChunkedBackendIsRedacted(t *testing.T) {
	_ = middleware.InitTrustedProxies(nil)
	const card = "4111 1111 1111 1111"

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No Content-Length + an explicit flush ⇒ chunked transfer encoding, the
		// exact response shape that bypassed DLP.
		_, _ = io.WriteString(w, `{"card":"`+card+`",`)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, `"email":"leak@example.com"}`)
	}))
	defer backend.Close()

	log := logger.New("error")
	gw, err := New([]config.RouteConfig{{
		Path:        "/",
		Upstreams:   []string{backend.URL},
		LoadBalance: "round_robin",
		Timeout:     "5s",
	}}, log)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	handler := middleware.DLP(config.DLPConfig{Enabled: true}, log, nopMetrics{})(gw)
	front := httptest.NewServer(handler)
	defer front.Close()

	resp, err := http.Get(front.URL + "/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	if strings.Contains(got, card) {
		t.Fatalf("card leaked through a chunked backend response (DLP bypassed): %q", got)
	}
	if strings.Contains(got, "leak@example.com") {
		t.Fatalf("email leaked through a chunked backend response: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("expected redaction marker in body, got %q", got)
	}
}
