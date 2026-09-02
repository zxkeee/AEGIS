package gateway

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/secevent"
)

// nopStore satisfies middleware.Store with no backing state, so a chain test can
// exercise every control without Redis. Nothing here is asserted on; the point
// is that the controls RUN and wrap the response writer.
type nopStore struct{}

func (nopStore) IncrRate(context.Context, string, time.Duration) (int64, error) { return 1, nil }
func (nopStore) IsIPBlocked(context.Context, string) (bool, error)              { return false, nil }
func (nopStore) BlockIP(context.Context, string) error                          { return nil }
func (nopStore) AutoBanIP(context.Context, string, time.Duration) error         { return nil }
func (nopStore) IncrMetric(context.Context, string)                             {}
func (nopStore) PushForensic(context.Context, secevent.Entry)                   {}
func (nopStore) IncrAutoBanCounter(context.Context, string) (int64, error)      { return 1, nil }
func (nopStore) RecordRequest(context.Context, string, string, int)             {}
func (nopStore) CalcBehaviorScore(context.Context, string, int) int             { return 0 }
func (nopStore) IncrBehaviorScore(context.Context, string, int)                 {}
func (nopStore) CheckJA3Consistency(context.Context, string, string) (bool, error) {
	return true, nil
}
func (nopStore) IssueChallenge(context.Context, string, string, time.Duration) error { return nil }
func (nopStore) IsValidChallengeToken(context.Context, string, string) (bool, error) {
	return true, nil
}
func (nopStore) MarkChallengeSolved(context.Context, string, time.Duration) error { return nil }
func (nopStore) IsChallengeSolved(context.Context, string) (bool, error)          { return true, nil }
func (nopStore) IsJTIRevoked(context.Context, string) (bool, error)               { return false, nil }
func (nopStore) TrackObjectAccess(context.Context, string, string, string, time.Duration) (int64, error) {
	return 1, nil
}
func (nopStore) TrackBaseline(context.Context, string, string, int64, bool, time.Duration) (float64, error) {
	return 0, nil
}
func (nopStore) TrackObjectOwner(context.Context, string, string, string, time.Duration) (int64, bool, error) {
	return 0, true, nil
}
func (nopStore) SetObjectOwner(context.Context, string, string, string, time.Duration) error {
	return nil
}
func (nopStore) GetObjectOwner(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}
func (nopStore) ValidateSession(context.Context, string) (iam.Session, bool, error) {
	return iam.Session{}, false, nil
}

// streamingBackend serves the two response shapes that must survive the chain:
// an SSE stream that flushes each event, and a connection upgrade that hijacks.
func streamingBackend(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// The stream stays open far longer than the assertion window on purpose. A
	// short stream would let the test pass even with flushing broken: the bytes
	// merely sit in the buffer and arrive together when the response ENDS, which
	// on a fast stream still lands inside the deadline. Only a stream that
	// outlives the deadline can distinguish "flushed as it happened" from
	// "delivered late in one lump" — the whole property under test.
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 300; i++ {
			select {
			case <-r.Context().Done(): // client went away; stop streaming
				return
			default:
			}
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			//nolint:errcheck // best-effort in a test backend
			http.NewResponseController(w).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	})
	// Registered as a subtree so the test can upgrade on a path carrying an
	// object id ("/ws/42"). That matters: AbuseDetection only wraps the response
	// writer when the request has a BOLA candidate, so a plain "/ws" would leave
	// its captureWriter out of the stack and quietly skip the layer that broke
	// DLP's hijack.
	mux.HandleFunc("/ws/", func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// allControlsOn is the shape that actually broke: every response-writer wrapper
// in the chain active at once. Each one is individually careful about streaming;
// the failure only appeared in composition.
func allControlsOn(upstream string) config.GatewayConfig {
	return config.GatewayConfig{
		Routes: []config.RouteConfig{{Path: "/", Upstreams: []string{upstream}}},
		Security: config.SecurityConfig{
			WAF: config.WAFConfig{Enabled: true, BlockMode: true},
			DLP: config.DLPConfig{Enabled: true},
			// ObjectOwnership is what makes AbuseDetection wrap the response
			// writer (captureWriter) — without it the deepest wrapper in the
			// stack is absent and the test would not exercise the real shape.
			Abuse:     config.AbuseConfig{Enabled: true, ObjectOwnership: true, OwnerFields: []string{"user_id"}},
			Behavior:  config.BehaviorConfig{Enabled: true, ScoreThreshold: 70, WindowSeconds: 60},
			Inventory: config.APIInventoryConfig{Enabled: true},
		},
	}
}

func chainServer(t *testing.T, cfg config.GatewayConfig) *httptest.Server {
	t.Helper()
	handler, _, err := BuildHandlerChain(cfg, logger.New("error"), nopStore{}, nil, discovery.NewPostureEngine(cfg), nil)
	if err != nil {
		t.Fatalf("BuildHandlerChain: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// Server-sent events must reach the client AS THEY HAPPEN, with every control
// enabled. They did not: Coraza's interceptor forwards a flush only when the
// writer it was handed satisfies a direct `w.(http.Flusher)` assertion, and
// middleware.wafStatusWriter offered only Unwrap. Every event sat in the buffer
// until the response ended — an SSE endpoint behind AEGIS delivered nothing at
// all, with the WAF on by default.
func TestChain_SSEStreamsWithEveryControlEnabled(t *testing.T) {
	be := streamingBackend(t)
	gw := chainServer(t, allControlsOn(be.URL))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gw.URL+"/sse", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /sse: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read the first two events. If flushing is broken they never arrive while
	// the stream is open and this blocks until the context deadline.
	got := make(chan string, 2)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data:") {
				select {
				case got <- sc.Text():
				default:
					return
				}
			}
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-got:
		case <-time.After(3 * time.Second):
			t.Fatal("no SSE event reached the client while the stream was open: a wrapper in the chain swallowed the flush")
		}
	}
}

// A protocol upgrade must reach the backend's hijack with every control
// enabled. It did not: Coraza only propagates an http.Hijacker when the writer
// it receives satisfies a direct type assertion, so the upgrade failed with
// "Hijack failed on protocol switch" and the client got a 502 — while three
// wrappers in this chain carried comments promising WebSocket support.
func TestChain_WebSocketUpgradeWithEveryControlEnabled(t *testing.T) {
	be := streamingBackend(t)
	gw := chainServer(t, allControlsOn(be.URL))

	addr := strings.TrimPrefix(gw.URL, "http://")
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "GET /ws/42 HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", addr); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("protocol upgrade did not survive the chain: got %q, want 101 Switching Protocols", strings.TrimSpace(status))
	}
}
