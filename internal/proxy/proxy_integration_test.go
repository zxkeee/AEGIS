package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
)

func testGW(t *testing.T, routes []config.RouteConfig) *Gateway {
	t.Helper()
	gw, err := New(routes, config.MultitenancyConfig{}, logger.New("error"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return gw
}

func TestNew_NoUpstreams_Error(t *testing.T) {
	_, err := New([]config.RouteConfig{{Path: "/x"}}, config.MultitenancyConfig{}, logger.New("error"))
	if err == nil {
		t.Fatal("route without upstreams must error")
	}
}

func TestNew_InvalidUpstream_Error(t *testing.T) {
	_, err := New([]config.RouteConfig{{Path: "/x", Upstreams: []string{"://bad"}}}, config.MultitenancyConfig{}, logger.New("error"))
	if err == nil {
		t.Fatal("invalid upstream URL must error")
	}
}

// TestProxy_MethodsEnforced is a regression test: route.Methods was declared
// in config and documented as an ACL but silently never checked anywhere in
// the request path — every method reached the backend regardless of what was
// configured (audit finding 2026-08-23).
func TestProxy_MethodsEnforced(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{
		Path: "/", Upstreams: []string{backend.URL}, Methods: []string{"GET", "POST"},
	}})

	for _, m := range []string{http.MethodGet, http.MethodPost} {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(m, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: allowed method got %d, want 200", m, rec.Code)
		}
	}

	for _, m := range []string{http.MethodPatch, http.MethodDelete, http.MethodPut} {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(m, "/x", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: disallowed method got %d, want 405 (this is the ACL bypass the finding described)", m, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow == "" {
			t.Errorf("%s: 405 response missing Allow header", m)
		}
	}
}

// An empty/unset route.Methods must remain unrestricted (the documented
// default) — the enforcement must not become a default-deny.
func TestProxy_MethodsUnset_Unrestricted(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{Path: "/", Upstreams: []string{backend.URL}}})
	for _, m := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(m, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: unrestricted route got %d, want 200", m, rec.Code)
		}
	}
}

// TestProxy_StripPrefix is a regression test: route.StripPrefix was also
// declared and documented but never applied — the backend always received the
// full incoming path, defeating the documented "mount a backend under its own
// root" use case and risking misrouting for any backend that assumes its own
// paths start at "/".
func TestProxy_StripPrefix(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Route paths are subtree patterns (trailing "/"), matching the convention
	// in config/gateway.yaml's own routes example.
	gw := testGW(t, []config.RouteConfig{{
		Path: "/api/orders/", Upstreams: []string{backend.URL}, StripPrefix: true,
	}})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/orders/42", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotPath != "/42" {
		t.Errorf("backend saw path %q, want /42 (prefix not stripped)", gotPath)
	}

	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/orders/", nil))
	if gotPath != "/" {
		t.Errorf("backend saw path %q for the bare route path, want /", gotPath)
	}
}

// Without StripPrefix (the default), the backend must keep seeing the full path.
func TestProxy_StripPrefix_DefaultOff(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{Path: "/api/orders/", Upstreams: []string{backend.URL}}})
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/orders/42", nil))
	if rec.Code != http.StatusOK || gotPath != "/api/orders/42" {
		t.Errorf("got path %q code %d, want /api/orders/42 200 (strip_prefix defaults off)", gotPath, rec.Code)
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

// TestProxy_CircuitBreakerOpenSkipsUpstreamThenExhausts covers the two
// branches New()'s registered handler has for a single, permanently-dead
// upstream: once its circuit breaker trips (5 failures, the fixed
// threshold), a further request must skip straight past the isOpen() check
// (`continue`) rather than dialing a known-bad upstream again, and — with
// only one upstream configured — immediately fall through to "All Upstreams
// Down" once the retry budget is spent on that skip.
func TestProxy_CircuitBreakerOpenSkipsUpstreamThenExhausts(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // now refuses connections

	gw := testGW(t, []config.RouteConfig{{Path: "/", Upstreams: []string{deadURL}, RetryAttempts: 1}})

	// Five failing requests trip the breaker (threshold is fixed at 5 in New()).
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("priming request %d: got %d, want 502 (dead upstream)", i, rec.Code)
		}
	}

	// The breaker is now open. The only upstream configured is skipped via
	// isOpen()->continue instead of being dialed again, and with a single
	// upstream and RetryAttempts=1 that immediately exhausts the loop.
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("after breaker trips: got %d, want 503 (all upstreams down/skipped)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "All Upstreams Down") {
		t.Fatalf("body = %q, want the all-upstreams-exhausted message", rec.Body.String())
	}
}

// TestProxy_StripPrefix_ExactRouteMatchBecomesRoot is a regression test for
// the edge of stripPrefix's own edge-case handling: TrimPrefix(path,
// routePrefix) is EMPTY (not "/") when the request path is an exact,
// no-trailing-slash match of the route's own prefix — this only arises for
// a route registered WITHOUT a trailing "/" (an exact-match ServeMux
// pattern), since a subtree ("/x/") pattern's shortest possible match already
// includes the boundary slash. Must still forward "/" to the backend, not "".
func TestProxy_StripPrefix_ExactRouteMatchBecomesRoot(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{
		Path: "/api/orders", Upstreams: []string{backend.URL}, StripPrefix: true,
	}})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/orders", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotPath != "/" {
		t.Errorf("backend saw path %q, want / (empty trim must become root, not empty string)", gotPath)
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
	rec := httptest.NewRecorder()
	aw := &attemptWriter{dst: rec, header: make(http.Header), status: http.StatusOK}
	aw.Header().Set("X-Test", "v")
	aw.WriteHeader(http.StatusCreated)
	aw.WriteHeader(http.StatusTeapot) // second call ignored
	_, _ = aw.Write([]byte("payload"))

	if rec.Body.Len() != 0 {
		t.Fatalf("bytes reached the client before commit: %q", rec.Body.String())
	}
	aw.commit()

	if rec.Code != http.StatusCreated {
		t.Fatalf("committed status = %d, want 201", rec.Code)
	}
	if rec.Body.String() != "payload" || rec.Header().Get("X-Test") != "v" {
		t.Fatalf("commit did not flush headers/body: %q %v", rec.Body.String(), rec.Header())
	}
}

func TestAttemptWriter_WriteImplicitOK(t *testing.T) {
	aw := &attemptWriter{dst: httptest.NewRecorder(), header: make(http.Header)}
	_, _ = aw.Write([]byte("x")) // Write without WriteHeader defaults to 200
	if aw.status != http.StatusOK || !aw.wrote {
		t.Fatalf("implicit WriteHeader failed: status=%d wrote=%v", aw.status, aw.wrote)
	}
}

// A Flush while buffering must commit what is already buffered to the real
// writer and switch to passthrough — this is what keeps SSE streaming through
// a buffered retry attempt instead of stalling until the stream ends.
func TestAttemptWriter_FlushCommitsAndStreams(t *testing.T) {
	rec := httptest.NewRecorder()
	aw := &attemptWriter{dst: rec, header: make(http.Header), status: http.StatusOK}
	aw.Header().Set("Content-Type", "text/event-stream")
	aw.WriteHeader(http.StatusOK)
	_, _ = aw.Write([]byte("data: one\n\n"))
	aw.Flush()

	if !aw.streamed {
		t.Fatal("Flush did not switch the writer to streamed mode")
	}
	if got := rec.Body.String(); got != "data: one\n\n" {
		t.Fatalf("first chunk not delivered on Flush: %q", got)
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("headers not committed on Flush: %v", rec.Header())
	}
	if !rec.Flushed {
		t.Fatal("flush was not propagated to the underlying writer")
	}

	// Subsequent writes go straight through.
	_, _ = aw.Write([]byte("data: two\n\n"))
	if got := rec.Body.String(); got != "data: one\n\ndata: two\n\n" {
		t.Fatalf("post-flush write was buffered: %q", got)
	}
}

// SSE must stream through the gateway in real time even when the retry path
// (buffered first attempt) is active. The old http.TimeoutHandler wrapper made
// this impossible: it buffered the whole response and implemented no Flusher.
func TestProxy_SSEStreamsThroughRetryPath(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: one\n\n")
		fl.Flush()
		<-release // hold the stream open until the client confirms receipt
		_, _ = io.WriteString(w, "data: two\n\n")
		fl.Flush()
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{
		Path: "/", Upstreams: []string{backend.URL}, RetryAttempts: 2, // retry path = buffered attempt
	}})
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The first chunk must arrive while the backend is still holding the stream
	// open. If the gateway buffers, this read blocks and the test times out.
	buf := make([]byte, 64)
	type readResult struct {
		n   int
		err error
	}
	got := make(chan readResult, 1)
	go func() {
		n, err := resp.Body.Read(buf)
		got <- readResult{n, err}
	}()
	select {
	case r := <-got:
		if r.err != nil || !strings.Contains(string(buf[:r.n]), "data: one") {
			t.Fatalf("first SSE chunk not streamed: n=%d err=%v body=%q", r.n, r.err, buf[:r.n])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway buffered the SSE stream: first chunk never arrived while stream open")
	}

	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("second SSE chunk lost: %q", rest)
	}
}

// The per-route timeout is now a time-to-response-headers bound on the
// transport. A stalled upstream must fail the attempt and fail over to the
// healthy one instead of hanging.
func TestProxy_HeaderTimeoutFailsOverToHealthy(t *testing.T) {
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second): // never answer within the route timeout
		}
	}))
	defer stall.Close()

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer healthy.Close()

	gw := testGW(t, []config.RouteConfig{{
		Path: "/", Upstreams: []string{stall.URL, healthy.URL}, RetryAttempts: 2, Timeout: "200ms",
	}})

	deadline := time.Now().Add(10 * time.Second)
	var sawOK bool
	for i := 0; i < 4 && time.Now().Before(deadline); i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code == http.StatusOK && rec.Body.String() == "ok" {
			sawOK = true
			break
		}
	}
	if !sawOK {
		t.Fatal("request never failed over from the stalled upstream to the healthy one")
	}
}

// Protocol upgrades (WebSocket) must pass through the gateway: the reverse
// proxy hijacks the client connection, which requires every writer between it
// and the server to support Hijack (directly or via Unwrap).
func TestProxy_WebSocketUpgradePassesThrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		line, _ := rw.ReadString('\n') // echo one line back
		_, _ = rw.WriteString("echo:" + line)
		_ = rw.Flush()
	}))
	defer backend.Close()

	gw := testGW(t, []config.RouteConfig{{
		Path: "/", Upstreams: []string{backend.URL}, RetryAttempts: 2,
	}})
	srv := httptest.NewServer(gw)
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("upgrade did not pass through the gateway: status=%q err=%v", status, err)
	}
	// Skip response headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	// Bidirectional bytes over the upgraded connection.
	_, _ = fmt.Fprintf(conn, "ping\n")
	echoed, err := br.ReadString('\n')
	if err != nil || echoed != "echo:ping\n" {
		t.Fatalf("upgraded connection is not bidirectional: %q err=%v", echoed, err)
	}
}

// A conflicting route pattern must come back as an error, never as a panic.
// http.ServeMux panics on a duplicate pattern, and proxy.New is called by
// gateway.BuildHandlerChain from the hot-reload goroutine, where nothing
// recovers — so before registerPattern, a duplicated path in a live config
// took the whole gateway down instead of leaving the previous config serving.
// config.Validate rejects the common shapes first; this asserts the backstop
// holds for anything ServeMux still refuses.
func TestNew_ConflictingRoutePatternIsAnErrorNotAPanic(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("proxy.New panicked instead of returning an error: %v", p)
		}
	}()
	_, err := New([]config.RouteConfig{
		{Path: "/orders", Upstreams: []string{"http://127.0.0.1:1"}},
		{Path: "/orders", Upstreams: []string{"http://127.0.0.1:2"}},
	}, config.MultitenancyConfig{}, logger.New("error"))
	if err == nil {
		t.Fatal("duplicate route pattern must return an error")
	}
	if !strings.Contains(err.Error(), "/orders") {
		t.Fatalf("error must name the conflicting pattern, got: %v", err)
	}
}

// Two tenants fronting the SAME path — one API surface, many customers — is
// multitenancy model A in ADR-001. It was structurally impossible: both routes
// registered the identical path pattern, so the gateway panicked at boot and
// the model existed only on paper. They are now registered host-scoped, so the
// Host header selects the tenant's own upstream.
func TestNew_TenantsShareOnePathRoutedByHost(t *testing.T) {
	acme := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "acme-backend")
	}))
	defer acme.Close()
	globex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "globex-backend")
	}))
	defer globex.Close()

	mt := config.MultitenancyConfig{
		Enabled: true,
		Tenants: []config.TenantConfig{
			{ID: "acme", Hosts: []string{"acme.example"}},
			{ID: "globex", Hosts: []string{"globex.example"}},
		},
	}
	gw, err := New([]config.RouteConfig{
		{Path: "/orders", TenantID: "acme", Upstreams: []string{acme.URL}},
		{Path: "/orders", TenantID: "globex", Upstreams: []string{globex.URL}},
	}, mt, logger.New("error"))
	if err != nil {
		t.Fatalf("two tenants sharing a path must build: %v", err)
	}

	get := func(host string) (int, string) {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/orders", nil)
		r.Host = host
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}

	if code, body := get("acme.example"); body != "acme-backend" {
		t.Fatalf("acme.example must reach acme's upstream, got %d %q", code, body)
	}
	if code, body := get("globex.example"); body != "globex-backend" {
		t.Fatalf("globex.example must reach globex's upstream, got %d %q", code, body)
	}
	// The Host is carried through a port, as ServeMux strips it before matching.
	if code, body := get("globex.example:8443"); body != "globex-backend" {
		t.Fatalf("a Host with a port must still match, got %d %q", code, body)
	}
	// An unknown Host on a shared path must NOT silently land on one tenant's
	// backend: the gateway genuinely cannot tell which tenant was meant, and
	// guessing would be a cross-tenant data leak.
	if code, _ := get("stranger.example"); code != http.StatusNotFound {
		t.Fatalf("unknown Host on a shared path must 404, got %d", code)
	}
}

// A route path claimed by ONE tenant keeps its bare pattern, so it is served
// whatever Host is used — ADR-001 makes the route's tenant_id authoritative,
// and host-scoping every route would silently break that for existing configs.
func TestNew_UnsharedTenantPathStillServesAnyHost(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "acme-backend")
	}))
	defer be.Close()

	mt := config.MultitenancyConfig{
		Enabled: true,
		Tenants: []config.TenantConfig{{ID: "acme", Hosts: []string{"acme.example"}}},
	}
	gw, err := New([]config.RouteConfig{
		{Path: "/orders", TenantID: "acme", Upstreams: []string{be.URL}},
	}, mt, logger.New("error"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, host := range []string{"acme.example", "10.0.0.7", "anything.internal"} {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/orders", nil)
		r.Host = host
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, r)
		if w.Body.String() != "acme-backend" {
			t.Fatalf("Host %q: unshared path must still be served, got %d %q", host, w.Code, w.Body.String())
		}
	}
}
