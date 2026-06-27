package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
)

// Gateway is a reverse proxy with load balancing and circuit breaking.
type Gateway struct {
	mux    *http.ServeMux
	log    *logger.Logger
	routes []config.RouteConfig
}

// New creates a Gateway from the route configuration.
func New(routes []config.RouteConfig, log *logger.Logger) (*Gateway, error) {
	gw := &Gateway{
		mux:    http.NewServeMux(),
		log:    log,
		routes: routes,
	}

	for _, route := range routes {
		if len(route.Upstreams) == 0 {
			return nil, fmt.Errorf("route %s has no upstreams", route.Path)
		}

		upstreams := make([]*upstream, 0, len(route.Upstreams))
		for _, u := range route.Upstreams {
			target, err := url.Parse(u)
			if err != nil {
				return nil, fmt.Errorf("invalid upstream %s: %w", u, err)
			}

			up := &upstream{
				url: target,
				cb:  newCircuitBreaker(5, 30*time.Second),
			}

			// FIX BUG-6: Wire circuit breaker into the error handler
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				up.cb.recordFailure() // <-- Circuit breaker now records failures
				log.Error("proxy error", map[string]any{
					"upstream": target.String(),
					"error":    err.Error(),
					"path":     r.URL.Path,
				})
				// If we're buffering this attempt for possible retry, just flag the
				// failure instead of committing a 502 to the client.
				if aw, ok := w.(*attemptWriter); ok {
					aw.failed = true
					return
				}
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			}

			// Modify the response to record success
			proxy.ModifyResponse = func(resp *http.Response) error {
				up.cb.recordSuccess() // <-- Reset circuit breaker on success
				return nil
			}

			up.proxy = proxy
			upstreams = append(upstreams, up)
		}

		lb := newLoadBalancer(upstreams, route.LoadBalance)

		timeout := 30 * time.Second
		if route.Timeout != "" {
			if d, err := time.ParseDuration(route.Timeout); err == nil {
				timeout = d
			}
		}

		retries := route.RetryAttempts
		if retries <= 0 {
			retries = 1
		}

		// FIX BUG-5: Capture loop variables explicitly for Go < 1.22 compatibility
		routePath := route.Path
		routeLB := lb
		routeTimeout := timeout
		routeRetries := retries

		gw.mux.HandleFunc(routePath, func(w http.ResponseWriter, r *http.Request) {
			retryable := isRetryable(r)

			// Retry logic with circuit breaker awareness.
			for attempt := 0; attempt < routeRetries; attempt++ {
				up := routeLB.next()
				if up == nil {
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
					return
				}

				// Circuit breaker check
				if up.cb.isOpen() {
					log.Warn("circuit_breaker: open, trying next upstream", map[string]any{
						"upstream": up.url.String(),
						"attempt":  attempt + 1,
					})
					continue
				}

				lastAttempt := attempt == routeRetries-1

				// For non-retryable requests (or the final attempt) stream the
				// response straight to the client — no point buffering.
				if !retryable || lastAttempt {
					http.TimeoutHandler(up.proxy, routeTimeout, "Gateway Timeout").ServeHTTP(w, r)
					return
				}

				// Buffer this attempt so a transport failure can fall through to
				// the next upstream without a partial response reaching the client.
				aw := &attemptWriter{header: make(http.Header), status: http.StatusOK}
				http.TimeoutHandler(up.proxy, routeTimeout, "Gateway Timeout").ServeHTTP(aw, r)

				if aw.failed {
					log.Warn("proxy: upstream failed, retrying next", map[string]any{
						"upstream": up.url.String(),
						"attempt":  attempt + 1,
					})
					continue
				}

				aw.commit(w)
				return
			}

			// All retries exhausted
			http.Error(w, "Service Unavailable (All Upstreams Down)", http.StatusServiceUnavailable)
		})

		log.Info("route registered", map[string]any{
			"path":      route.Path,
			"upstreams": route.Upstreams,
			"lb":        route.LoadBalance,
			"retries":   retries,
		})
	}

	return gw, nil
}

// ServeHTTP implements http.Handler.
func (gw *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	gw.mux.ServeHTTP(w, r)
}

// isRetryable reports whether a request can be safely re-sent to another
// upstream after a transport failure. Only idempotent methods without a body
// are retried — replaying a POST/PATCH could execute a side effect twice, and
// the request body has already been consumed by the first attempt.
func isRetryable(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return r.Body == nil || r.ContentLength == 0
	default:
		return false
	}
}

// attemptWriter buffers a single proxy attempt so that, on transport failure,
// the gateway can retry the next upstream without having sent partial bytes to
// the client. On success the buffered response is committed verbatim.
type attemptWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	failed bool // set by the proxy ErrorHandler on transport failure
	wrote  bool
}

func (a *attemptWriter) Header() http.Header { return a.header }

func (a *attemptWriter) WriteHeader(code int) {
	if a.wrote {
		return
	}
	a.wrote = true
	a.status = code
}

func (a *attemptWriter) Write(b []byte) (int, error) {
	if !a.wrote {
		a.WriteHeader(http.StatusOK)
	}
	return a.body.Write(b)
}

// commit flushes the buffered headers, status, and body to the real writer.
func (a *attemptWriter) commit(w http.ResponseWriter) {
	dst := w.Header()
	for k, vs := range a.header {
		dst[k] = vs
	}
	w.WriteHeader(a.status)
	w.Write(a.body.Bytes()) //nolint:errcheck
}

// ── Load Balancer ─────────────────────────────────────────────────────────────

type upstream struct {
	url   *url.URL
	proxy *httputil.ReverseProxy
	cb    *circuitBreaker
}

type loadBalancer struct {
	upstreams []*upstream
	counter   uint64
	strategy  string
}

func newLoadBalancer(ups []*upstream, strategy string) *loadBalancer {
	if strategy == "" {
		strategy = "round_robin"
	}
	return &loadBalancer{upstreams: ups, strategy: strategy}
}

func (lb *loadBalancer) next() *upstream {
	if len(lb.upstreams) == 0 {
		return nil
	}

	n := atomic.AddUint64(&lb.counter, 1)
	return lb.upstreams[n%uint64(len(lb.upstreams))]
}

// ── Circuit Breaker ───────────────────────────────────────────────────────────

type circuitBreaker struct {
	mu         sync.Mutex
	failures   int
	threshold  int
	resetAfter time.Duration
	lastFail   time.Time
	open       bool
	probing    bool // a single half-open probe is in flight
}

func newCircuitBreaker(threshold int, resetAfter time.Duration) *circuitBreaker {
	return &circuitBreaker{
		threshold:  threshold,
		resetAfter: resetAfter,
	}
}

func (cb *circuitBreaker) isOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.open && time.Since(cb.lastFail) > cb.resetAfter {
		// Half-open: let exactly ONE probe through to test recovery and keep
		// blocking everyone else until it resolves. The previous code cleared
		// `open` here, which let every concurrent request hit a still-unhealthy
		// upstream — defeating the breaker at the worst moment. recordSuccess
		// closes the breaker; recordFailure re-arms it for the next window.
		if cb.probing {
			return true // a probe is already in flight; stay open to others
		}
		cb.probing = true
		return false // this request is the probe
	}
	return cb.open
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFail = time.Now()
	cb.probing = false // a failed probe re-opens; a new probe is allowed next window
	if cb.failures >= cb.threshold {
		cb.open = true
	}
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.open = false
	cb.probing = false
}
