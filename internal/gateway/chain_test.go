package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
)

// TestChainOrder pins the data-plane middleware order. The ordering is
// load-bearing (e.g. TenantResolve must be first, CleanHeaders must strip
// spoofed identity before anything trusts it, Discovery must sit inside the
// security perimeter but outside auth/DLP, AbuseDetection must run after auth so
// it sees verified roles). An accidental reorder must fail here, not in prod.
//
// The expected slice intentionally duplicates the wiring in chainSteps: that is
// the point of a golden test — the two must be changed together and a reviewer
// sees the order move explicitly in the diff.
func TestChainOrder(t *testing.T) {
	want := []string{
		"TenantResolve",
		"CleanHeaders",
		"LicenseRateLimit",
		"UpstreamFingerprint",
		"TLSFingerprint",
		"SecurityHeaders",
		"RequestID",
		"PathSanity",
		"CORS",
		"IPGuard",
		"ThreatFeed",
		"RateLimit",
		"BotProtection",
		"Challenge",
		"WAF",
		"Discovery",
		"Auth",
		"ConsumerID",
		"SchemaValidation",
		"AbuseDetection",
		"DLP",
		"BehaviorAnalysis",
	}

	cfg := config.GatewayConfig{}
	log := logger.New("error")
	postureEng := discovery.NewPostureEngine(cfg)

	// With every control disabled the constructors return passthrough without
	// ever touching the store, so a nil Store is sufficient to assemble — and
	// pin the order of — the chain without a live Redis.
	steps := chainSteps(cfg, log, nil, nil, postureEng, nil)

	if len(steps) != len(want) {
		t.Fatalf("chain length = %d, want %d", len(steps), len(want))
	}
	for i, s := range steps {
		if s.name != want[i] {
			t.Errorf("chain position %d = %q, want %q", i, s.name, want[i])
		}
	}
}

// TestBuildHandlerChain_NilCatalog ensures a nil *discovery.Catalog yields a
// working handler (the Discovery middleware must degrade to passthrough, not
// panic on a typed-nil interface).
func TestBuildHandlerChain_NilCatalog(t *testing.T) {
	cfg := config.GatewayConfig{
		Routes: []config.RouteConfig{{Path: "/", Upstreams: []string{"http://127.0.0.1:9"}}},
	}
	log := logger.New("error")
	postureEng := discovery.NewPostureEngine(cfg)

	handler, gw, err := BuildHandlerChain(cfg, log, nil, nil, postureEng)
	if err != nil {
		t.Fatalf("BuildHandlerChain: %v", err)
	}
	if handler == nil || gw == nil {
		t.Fatal("BuildHandlerChain returned nil handler or gateway")
	}
}

func TestExactMatchRoutes(t *testing.T) {
	r := func(paths ...string) []config.RouteConfig {
		out := make([]config.RouteConfig, 0, len(paths))
		for _, p := range paths {
			out = append(out, config.RouteConfig{Path: p, Upstreams: []string{"http://127.0.0.1:1"}})
		}
		return out
	}

	tests := []struct {
		name   string
		routes []config.RouteConfig
		want   []string
	}{
		{
			// The footgun itself: item paths under this route 404 at the proxy
			// while the posture engine reports them as covered.
			name:   "collection without trailing slash",
			routes: r("/api/v1/customers"),
			want:   []string{"/api/v1/customers"},
		},
		{
			// Both forms declared — the operator clearly knows the distinction.
			name:   "both forms declared is silent",
			routes: r("/api/v1/orders", "/api/v1/orders/"),
			want:   nil,
		},
		{
			// A single-segment path is idiomatically an exact endpoint.
			name:   "single-segment path is silent",
			routes: r("/health", "/metrics"),
			want:   nil,
		},
		{
			name:   "subtree route is silent",
			routes: r("/internal/"),
			want:   nil,
		},
		{
			// Only the genuine offenders, in declaration order: /api/v1/orders is
			// paired with its subtree form and /health is single-segment.
			name:   "reports every offender and nothing else",
			routes: r("/api/v1/customers", "/api/v1/orders", "/api/v1/orders/", "/health", "/internal/reports"),
			want:   []string{"/api/v1/customers", "/internal/reports"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exactMatchRoutes(tt.routes)
			if len(got) != len(tt.want) {
				t.Fatalf("exactMatchRoutes = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("exactMatchRoutes = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestBuildHandlerChain_WarnsAboutExactMatchRoutes pins that the warning is
// actually WIRED IN, not merely implemented.
//
// exactMatchRoutes is covered on its own above, but that proves nothing about
// whether anyone calls it: deleting the call from BuildHandlerChain left the
// entire suite green when this was checked by mutation. The whole value of the
// warning is that it reaches an operator at startup, so the call site is the
// thing worth pinning.
//
// The logger writes to os.Stdout with no seam to inject, so the test captures
// the real descriptor.
func TestBuildHandlerChain_WarnsAboutExactMatchRoutes(t *testing.T) {
	cfg := config.GatewayConfig{
		Routes: []config.RouteConfig{
			{Path: "/api/v1/customers", Upstreams: []string{"http://127.0.0.1:9"}},
		},
	}
	postureEng := discovery.NewPostureEngine(cfg)

	out := captureStdout(t, func() {
		if _, _, err := BuildHandlerChain(cfg, logger.New("warn"), nil, nil, postureEng); err != nil {
			t.Fatalf("BuildHandlerChain: %v", err)
		}
	})

	if !strings.Contains(out, "trailing slash") {
		t.Fatalf("startup output does not warn about the exact-match route.\ngot: %s", out)
	}
	if !strings.Contains(out, "/api/v1/customers") {
		t.Fatalf("warning does not name the offending route.\ngot: %s", out)
	}
}

// TestBuildHandlerChain_SilentOnWellFormedRoutes is the other half: a config
// that declares both forms must not produce the warning, or operators learn to
// ignore it.
func TestBuildHandlerChain_SilentOnWellFormedRoutes(t *testing.T) {
	cfg := config.GatewayConfig{
		Routes: []config.RouteConfig{
			{Path: "/api/v1/customers", Upstreams: []string{"http://127.0.0.1:9"}},
			{Path: "/api/v1/customers/", Upstreams: []string{"http://127.0.0.1:9"}},
			{Path: "/health", Upstreams: []string{"http://127.0.0.1:9"}},
		},
	}
	postureEng := discovery.NewPostureEngine(cfg)

	out := captureStdout(t, func() {
		if _, _, err := BuildHandlerChain(cfg, logger.New("warn"), nil, nil, postureEng); err != nil {
			t.Fatalf("BuildHandlerChain: %v", err)
		}
	})

	if strings.Contains(out, "trailing slash") {
		t.Fatalf("warned about a correctly-declared config.\ngot: %s", out)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what was
// written. The pipe is drained concurrently so a chatty fn cannot fill the pipe
// buffer and deadlock.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	os.Stdout = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatalf("close pipe reader: %v", err)
	}
	return out
}

// countingStore records how many times the per-IP rate limiter was consulted, so
// a test can tell "the limiter did not run" from "it ran and allowed".
type countingStore struct {
	nopStore
	mu   sync.Mutex
	seen map[string]int64
}

func (c *countingStore) IncrRate(_ context.Context, key string, _ time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]int64{}
	}
	c.seen[key]++
	return c.seen[key], nil
}

// The admin plane's 5/s per-IP limiter must never cover the liveness and
// readiness probes. It is keyed by RealIP, so with trusted_proxies unset every
// request through a load balancer shares the balancer's bucket — an
// unauthenticated caller could spend the budget and push /readyz to 429, at
// which point the balancer pulls the instance from rotation. A full outage,
// triggered from outside, with no credential.
func TestBuildAdminChain_ProbesAreNotRateLimited(t *testing.T) {
	st := &countingStore{}
	cfg := config.GatewayConfig{AdminAuth: true, AdminSecret: "a-strong-admin-secret-32-characters!!"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := BuildAdminChain(inner, cfg, logger.New("error"), st, nil)

	// Far more than the 5/s budget: every probe must still be served.
	for _, path := range []string{"/health", "/readyz"} {
		for i := 0; i < 30; i++ {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s request %d: got %d, want 200 — a throttled probe gets the instance pulled from rotation",
					path, i+1, rec.Code)
			}
		}
	}
	st.mu.Lock()
	consulted := len(st.seen)
	st.mu.Unlock()
	if consulted != 0 {
		t.Errorf("the rate limiter was consulted for probe traffic (%d keys); probes must bypass it entirely", consulted)
	}
}

// ...while the admin API itself stays throttled: that limiter exists to absorb
// unauthenticated brute force, and exempting the probes must not exempt anything
// else.
func TestBuildAdminChain_AdminAPIStaysRateLimited(t *testing.T) {
	st := &countingStore{}
	cfg := config.GatewayConfig{AdminAuth: true, AdminSecret: "a-strong-admin-secret-32-characters!!"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := BuildAdminChain(inner, cfg, logger.New("error"), st, nil)

	var throttled bool
	for i := 0; i < 12; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Error("admin API traffic was never throttled; the brute-force limiter is not running")
	}
}
