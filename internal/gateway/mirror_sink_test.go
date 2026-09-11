package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
)

// The promise that makes a mirrored deployment acceptable is that the
// customer's backend is never touched. A mirrored POST forwarded upstream
// would be a replayed write against production — the exact harm the deployment
// shape was chosen to avoid.
func TestMirrorSink_NeverForwardsUpstream(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.GatewayConfig{
		MirrorSink: true,
		Observe:    true,
		Routes:     []config.RouteConfig{{Path: "/", Upstreams: []string{upstream.URL}}},
	}
	h, _, err := BuildHandlerChain(cfg, logger.New("error"), nil, nil,
		discovery.NewPostureEngine(cfg), nil)
	if err != nil {
		t.Fatalf("BuildHandlerChain: %v", err)
	}

	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/api/orders/42", strings.NewReader(`{"x":1}`)))
		if rec.Code != http.StatusNoContent {
			t.Errorf("%s answered %d, want 204", m, rec.Code)
		}
	}
	if n := atomic.LoadInt32(&upstreamHits); n != 0 {
		t.Fatalf("the upstream was called %d times; a mirrored request must never be "+
			"forwarded — that would replay writes against the customer's backend", n)
	}
}

// Without the sink, the same config forwards. This is the control: it proves
// the test above passes because of MirrorSink and not because the chain is
// broken.
func TestMirrorSink_OffStillForwards(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.GatewayConfig{
		Routes: []config.RouteConfig{{Path: "/", Upstreams: []string{upstream.URL}}},
	}
	h, _, err := BuildHandlerChain(cfg, logger.New("error"), nil, nil,
		discovery.NewPostureEngine(cfg), nil)
	if err != nil {
		t.Fatalf("BuildHandlerChain: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/orders/42", nil))
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream hits = %d, want 1: without MirrorSink the chain must proxy",
			atomic.LoadInt32(&upstreamHits))
	}
}
