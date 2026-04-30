package proxy

import (
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
			// Retry logic with circuit breaker awareness
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

				// Set timeout
				http.TimeoutHandler(up.proxy, routeTimeout, "Gateway Timeout").ServeHTTP(w, r)
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
		// Half-open: allow one request to test recovery
		cb.open = false
		cb.failures = 0
	}
	return cb.open
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFail = time.Now()
	if cb.failures >= cb.threshold {
		cb.open = true
	}
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.open = false
}
