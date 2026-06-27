package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
)

func testGW(t *testing.T, routes []config.RouteConfig) *Gateway {
	t.Helper()
	gw, err := New(routes, logger.New("error"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return gw
}

func TestNew_NoUpstreams_Error(t *testing.T) {
	_, err := New([]config.RouteConfig{{Path: "/x"}}, logger.New("error"))
	if err == nil {
		t.Fatal("route without upstreams must error")
	}
}

func TestNew_InvalidUpstream_Error(t *testing.T) {
	_, err := New([]config.RouteConfig{{Path: "/x", Upstreams: []string{"://bad"}}}, logger.New("error"))
	if err == nil {
		t.Fatal("invalid upstream URL must error")
	}
}

func TestProxy_ForwardsToBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "1")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "hello")
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{Path: "/", Upstreams: []string{backend.URL}}})
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	if rec.Body.String() != "hello" || rec.Header().Get("X-Backend") != "1" {
		t.Fatalf("response not proxied verbatim: %q %v", rec.Body.String(), rec.Header())
	}
}

func TestProxy_RoundRobinAcrossBackends(t *testing.T) {
	var aHits, bHits int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { atomic.AddInt32(&aHits, 1) }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { atomic.AddInt32(&bHits, 1) }))
	defer b.Close()

	gw := testGW(t, []config.RouteConfig{{
		Path: "/", Upstreams: []string{a.URL, b.URL}, LoadBalance: "round_robin",
	}})
	for i := 0; i < 6; i++ {
		gw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if atomic.LoadInt32(&aHits) == 0 || atomic.LoadInt32(&bHits) == 0 {
		t.Fatalf("round-robin did not spread load: a=%d b=%d", aHits, bHits)
	}
}

func TestProxy_RetriesToHealthyUpstream(t *testing.T) {
	// First upstream is a closed server (transport failure); the GET must fail
	// over to the healthy one and return 200.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // now refuses connections

	var healthyHits int32
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&healthyHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	gw := testGW(t, []config.RouteConfig{{
		Path: "/", Upstreams: []string{deadURL, healthy.URL}, RetryAttempts: 2,
	}})

	// counter starts at 0; next() does AddUint64 → first pick is index 1 (healthy),
	// so drive a few requests to ensure the dead-first ordering is exercised too.
	var got200 bool
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code == http.StatusOK {
			got200 = true
		}
	}
	if !got200 || atomic.LoadInt32(&healthyHits) == 0 {
		t.Fatalf("failover did not reach healthy upstream (hits=%d)", healthyHits)
	}
}

func TestProxy_POSTNotRetried(t *testing.T) {
	// A POST is non-idempotent: even with retries configured it must hit the
	// backend at most once per request (no replay).
	var hits int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{Path: "/", Upstreams: []string{backend.URL}, RetryAttempts: 3}})
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body")))
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("POST hit backend %d times, want 1 (no retry replay)", hits)
	}
}

func TestAttemptWriter_BuffersThenCommits(t *testing.T) {
	aw := &attemptWriter{header: make(http.Header), status: http.StatusOK}
	aw.Header().Set("X-Test", "v")
	aw.WriteHeader(http.StatusCreated)
	aw.WriteHeader(http.StatusTeapot) // second call ignored
	_, _ = aw.Write([]byte("payload"))

	rec := httptest.NewRecorder()
	aw.commit(rec)

	if rec.Code != http.StatusCreated {
		t.Fatalf("committed status = %d, want 201", rec.Code)
	}
	if rec.Body.String() != "payload" || rec.Header().Get("X-Test") != "v" {
		t.Fatalf("commit did not flush headers/body: %q %v", rec.Body.String(), rec.Header())
	}
}

func TestAttemptWriter_WriteImplicitOK(t *testing.T) {
	aw := &attemptWriter{header: make(http.Header)}
	_, _ = aw.Write([]byte("x")) // Write without WriteHeader defaults to 200
	if aw.status != http.StatusOK || !aw.wrote {
		t.Fatalf("implicit WriteHeader failed: status=%d wrote=%v", aw.status, aw.wrote)
	}
}
