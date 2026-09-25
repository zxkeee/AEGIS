package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
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
//
// mt supplies the tenant → Host mapping. It is needed because two tenants may
// legitimately front the SAME path (one API surface, many customers — model A
// in ADR-001), which the path-only mux cannot express: both would register an
// identical pattern. Such routes are registered host-scoped instead, so the
// Host header picks the tenant. Pass a zero MultitenancyConfig for
// single-tenant deployments; nothing about their routing changes.
func New(routes []config.RouteConfig, mt config.MultitenancyConfig, log *logger.Logger) (*Gateway, error) {
	gw := &Gateway{
		mux:    http.NewServeMux(),
		log:    log,
		routes: routes,
	}

	hostsOf := tenantHosts(mt)
	shared := sharedPaths(routes, mt)

	for _, route := range routes {
		if len(route.Upstreams) == 0 {
			return nil, fmt.Errorf("route %s has no upstreams", route.Path)
		}

		timeout := 30 * time.Second
		if route.Timeout != "" {
			if d, err := time.ParseDuration(route.Timeout); err == nil {
				timeout = d
			}
		}

		// One transport per route enforces the upstream timeout as a
		// time-to-response-headers bound. The previous http.TimeoutHandler wrapper
		// is gone: it buffered every response fully in memory (unbounded — a large
		// upstream body times concurrency was an OOM vector) and implements
		// neither Flusher nor Hijacker, which silently broke SSE and WebSocket
		// despite the DLP layer supporting both. Body streaming time is bounded by
		// the server's WriteTimeout, not per-route config.
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = timeout

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
			proxy.Transport = transport
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				up.cb.recordFailure() // <-- Circuit breaker now records failures
				log.Error("proxy error", map[string]any{
					"upstream": target.String(),
					"error":    err.Error(),
					"path":     r.URL.Path,
				})
				// If we're buffering this attempt for possible retry, just flag the
				// failure instead of committing a 502 to the client — unless bytes
				// already streamed to the client, in which case the response is
				// unsalvageable either way.
				if aw, ok := w.(*attemptWriter); ok && !aw.streamed {
					aw.failed = true
					return
				}
				if aw, ok := w.(*attemptWriter); ok && aw.streamed {
					return // partial response already on the wire; nothing to write
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

		retries := route.RetryAttempts
		if retries <= 0 {
			retries = 1
		}

		// FIX BUG-5: Capture loop variables explicitly for Go < 1.22 compatibility
		routePath := route.Path
		routeLB := lb
		routeRetries := retries

		// allowedMethods enforces route.Methods (SEC: was declared in config and
		// documented as an ACL but silently never checked — every method reached
		// the backend regardless of what the operator configured; audit finding
		// 2026-08-23). An empty list means "no restriction," matching the
		// documented default. Built once per route, not per request.
		var allowedMethods map[string]bool
		if len(route.Methods) > 0 {
			allowedMethods = make(map[string]bool, len(route.Methods))
			for _, m := range route.Methods {
				allowedMethods[strings.ToUpper(m)] = true
			}
		}

		// stripPrefix removes the matched route.Path from the forwarded request
		// (SEC: also declared and documented but never applied — see above).
		// http.ServeMux's routePath may or may not end in "/"; strip exactly the
		// segment the route matched on, mirroring how the pattern was registered.
		stripPrefix := route.StripPrefix
		routePrefix := strings.TrimSuffix(routePath, "/")

		handler := func(w http.ResponseWriter, r *http.Request) {
			if allowedMethods != nil && !allowedMethods[r.Method] {
				allow := make([]string, 0, len(allowedMethods))
				for m := range allowedMethods {
					allow = append(allow, m)
				}
				sort.Strings(allow)
				w.Header().Set("Allow", strings.Join(allow, ", "))
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}

			if stripPrefix {
				trimmed := strings.TrimPrefix(r.URL.Path, routePrefix)
				if trimmed == "" {
					trimmed = "/"
				} else if !strings.HasPrefix(trimmed, "/") {
					trimmed = "/" + trimmed
				}
				r.URL.Path = trimmed
				if r.URL.RawPath != "" {
					r.URL.RawPath = trimmed
				}
			}

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
					up.proxy.ServeHTTP(w, r)
					return
				}

				// Buffer this attempt so a transport failure can fall through to
				// the next upstream without a partial response reaching the client.
				// A Flush (SSE) or Hijack (WebSocket) commits straight to the real
				// writer instead — once bytes are on the wire a retry is impossible
				// anyway, and buffering would break the stream.
				aw := &attemptWriter{dst: w, header: make(http.Header), status: http.StatusOK}
				up.proxy.ServeHTTP(aw, r)

				if aw.streamed {
					return // response (or part of it) already delivered
				}
				if aw.failed {
					log.Warn("proxy: upstream failed, retrying next", map[string]any{
						"upstream": up.url.String(),
						"attempt":  attempt + 1,
					})
					continue
				}

				aw.commit()
				return
			}

			// All retries exhausted
			http.Error(w, "Service Unavailable (All Upstreams Down)", http.StatusServiceUnavailable)
		}

		patterns, err := routePatterns(route, hostsOf[route.TenantID], shared[route.Path])
		if err != nil {
			return nil, err
		}
		for _, p := range patterns {
			if err := registerPattern(gw.mux, p, handler); err != nil {
				return nil, err
			}
		}

		log.Info("route registered", map[string]any{
			"patterns":     patterns,
			"tenant":       route.TenantID,
			"path":         route.Path,
			"upstreams":    route.Upstreams,
			"lb":           route.LoadBalance,
			"retries":      retries,
			"methods":      route.Methods, // empty = unrestricted
			"strip_prefix": route.StripPrefix,
		})
	}

	return gw, nil
}

// tenantHosts indexes the configured Host names by tenant id. Empty when
// multi-tenancy is off, which makes every route below fall into the plain
// path-pattern case — the single-tenant behaviour, unchanged.
func tenantHosts(mt config.MultitenancyConfig) map[string][]string {
	if !mt.Enabled {
		return nil
	}
	out := make(map[string][]string, len(mt.Tenants))
	for _, t := range mt.Tenants {
		out[t.ID] = t.Hosts
	}
	return out
}

// sharedPaths reports which route paths are claimed by more than one tenant.
// Those are the only routes that MUST be host-scoped; every other route keeps
// its bare path pattern so a request is still served regardless of Host, which
// is what ADR-001 means by "the route's tenant_id is authoritative".
func sharedPaths(routes []config.RouteConfig, mt config.MultitenancyConfig) map[string]bool {
	if !mt.Enabled {
		return nil
	}
	owners := make(map[string]string, len(routes))
	shared := make(map[string]bool)
	for _, r := range routes {
		if owner, seen := owners[r.Path]; seen && owner != r.TenantID {
			shared[r.Path] = true
			continue
		}
		owners[r.Path] = r.TenantID
	}
	return shared
}

// routePatterns returns the http.ServeMux patterns one route registers.
//
//   - No hosts (or single-tenant): just the bare path, as before.
//   - Hosts declared: one "<host><path>" pattern per host, PLUS the bare path
//     when no other tenant claims it. Host patterns are the more specific match,
//     so they win when the Host matches and the bare pattern keeps serving
//     everything else — no behaviour change for existing configs.
//   - Hosts declared and the path IS shared: host patterns only. A request whose
//     Host matches no tenant then 404s, which is correct: the gateway genuinely
//     cannot tell which tenant's backend was meant.
func routePatterns(route config.RouteConfig, hosts []string, isShared bool) ([]string, error) {
	if len(hosts) == 0 {
		if isShared {
			// config.validateRoutes rejects this shape with a fuller message;
			// this keeps proxy.New self-contained rather than trusting a caller
			// to have validated first.
			return nil, fmt.Errorf("route %q is shared by several tenants but tenant %q declares no hosts to route it by",
				route.Path, route.TenantID)
		}
		return []string{route.Path}, nil
	}
	patterns := make([]string, 0, len(hosts)+1)
	for _, h := range hosts {
		patterns = append(patterns, hostPattern(h, route.Path))
	}
	if !isShared {
		patterns = append(patterns, route.Path)
	}
	return patterns, nil
}

// hostPattern splices a Host into a route path to form a ServeMux pattern,
// keeping a leading "METHOD " where an operator wrote one ("GET /orders" ->
// "GET acme.example/orders"), since the method must stay the first token.
func hostPattern(host, path string) string {
	if i := strings.IndexByte(path, ' '); i >= 0 {
		return path[:i+1] + host + path[i+1:]
	}
	return host + path
}

// registerPattern registers one route pattern, converting the panic
// http.ServeMux raises on a conflicting pattern into an ordinary error. New is
// called from the hot-reload goroutine, where an unrecovered panic kills the
// process instead of rejecting the reload.
//
// Deliberately a recover, not a pre-computed duplicate check: ServeMux decides
// conflicts by its own pattern-precedence rules (wildcards, method and host
// prefixes all participate), so any check here would be a second copy of those
// rules, free to drift. config.validateRoutes catches the common shapes early
// with a better message; this is the backstop for everything else.
func registerPattern(mux *http.ServeMux, pattern string, h http.HandlerFunc) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("route %q cannot be registered: %v", pattern, p)
		}
	}()
	mux.HandleFunc(pattern, h)
	return nil
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
//
// Streaming escape hatches: a Flush (the reverse proxy flushes immediately for
// text/event-stream and unknown-length streaming bodies) commits the buffered
// state to the real writer and switches to passthrough; a Hijack (WebSocket /
// protocol upgrade) hands the connection over directly. In both cases
// `streamed` is set, telling the retry loop that this response is already on
// the wire and no further attempt may run.
type attemptWriter struct {
	dst      http.ResponseWriter
	header   http.Header
	status   int
	body     bytes.Buffer
	failed   bool // set by the proxy ErrorHandler on transport failure
	wrote    bool
	streamed bool // committed to dst mid-flight (Flush/Hijack); retry impossible
}

func (a *attemptWriter) Header() http.Header {
	if a.streamed {
		return a.dst.Header()
	}
	return a.header
}

func (a *attemptWriter) WriteHeader(code int) {
	if a.streamed {
		return // header already committed to dst
	}
	if a.wrote {
		return
	}
	a.wrote = true
	a.status = code
}

// maxAttemptBufferSize bounds how much of an upstream response body attemptWriter
// buffers in memory for retry. A response larger than this switches to
// passthrough streaming directly to the client: once bytes hit the wire a retry
// is impossible anyway, and buffering an unbounded body (large downloads,
// videos, exports) is an OOM vector against the gateway process.
const maxAttemptBufferSize = 4 << 20 // 4 MB

func (a *attemptWriter) Write(b []byte) (int, error) {
	if a.streamed {
		return a.dst.Write(b)
	}
	if !a.wrote {
		a.WriteHeader(http.StatusOK)
	}
	if a.body.Len()+len(b) > maxAttemptBufferSize {
		// Response exceeds buffer budget: commit what we have, switch to streamed
		// passthrough so memory stays bounded. A transport failure after this point
		// cannot be retried, matching the behavior of non-buffered streaming.
		a.commit()
		return a.dst.Write(b)
	}
	return a.body.Write(b)
}

// commit flushes the buffered headers, status, and body to the real writer and
// switches the writer into passthrough mode.
func (a *attemptWriter) commit() {
	if a.streamed {
		return
	}
	dst := a.dst.Header()
	for k, vs := range a.header {
		dst[k] = vs
	}
	a.dst.WriteHeader(a.status)
	if a.body.Len() > 0 {
		a.dst.Write(a.body.Bytes()) //nolint:errcheck
		a.body.Reset()
	}
	a.streamed = true
}

// Flush implements http.Flusher: the response has begun streaming, so commit
// everything buffered so far and pass the flush through. The reverse proxy
// calls this immediately for Content-Type: text/event-stream, which is what
// keeps SSE working through the gateway even on buffered retry attempts.
// ResponseController is used (rather than a direct type assertion) so the
// flush reaches the real writer through any middleware wrappers that expose
// Unwrap().
func (a *attemptWriter) Flush() {
	a.commit()
	_ = http.NewResponseController(a.dst).Flush()
}

// Hijack implements http.Hijacker so protocol upgrades (WebSocket) work on
// buffered retry attempts: the connection is handed to the caller and this
// attempt can never be retried.
func (a *attemptWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(a.dst).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: hijack: %w", err)
	}
	a.streamed = true
	return conn, rw, nil
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
