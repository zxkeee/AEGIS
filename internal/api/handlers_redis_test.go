package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// redisHandlers builds a *handlers backed by an in-memory Redis (miniredis), so
// the store-touching admin handlers can be exercised in plain `go test ./...`
// with no external services. AdminAuth is disabled at the config level; RBAC is
// still enforced via the role threaded into the request context (see ctxAs).
func redisHandlers(t *testing.T) (*handlers, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.GatewayConfig{
		Listen:      ":8080",
		AdminListen: ":8081",
		AdminAuth:   false,
		AdminSecret: "test-secret-min-32-characters-1234",
		Routes:      []config.RouteConfig{{Path: "/a/", Upstreams: []string{"http://x"}}},
	}
	return &handlers{store: st, log: logger.New("error"), cfg: cfg}, mr
}

func TestReadyz_OK(t *testing.T) {
	h, _ := redisHandlers(t)
	rec, body := doReq(h.readyz, http.MethodGet, "/readyz", context.Background(), nil)
	if rec.Code != http.StatusOK || body["status"] != "ready" {
		t.Fatalf("readyz = %d %v", rec.Code, body)
	}
}

func TestReadyz_RedisDown(t *testing.T) {
	h, mr := redisHandlers(t)
	mr.Close() // simulate a Redis outage
	rec, body := doReq(h.readyz, http.MethodGet, "/readyz", context.Background(), nil)
	if rec.Code != http.StatusServiceUnavailable || body["status"] != "not_ready" {
		t.Fatalf("readyz down = %d %v", rec.Code, body)
	}
}

// TestReadyz_DrainingWinsOverHealthyRedis proves the lame-duck path: once the
// server is draining, /readyz reports 503 even though Redis is fully up, so an
// upstream load balancer removes the instance before the listener closes.
func TestReadyz_DrainingWinsOverHealthyRedis(t *testing.T) {
	h, _ := redisHandlers(t)
	var draining atomic.Bool
	h.draining = &draining

	// Not draining yet: Redis is up, so ready.
	rec, body := doReq(h.readyz, http.MethodGet, "/readyz", context.Background(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-drain readyz = %d %v", rec.Code, body)
	}

	// Begin draining: readyz must flip to 503 not_ready with the drain reason,
	// even though Redis is still reachable.
	draining.Store(true)
	rec, body = doReq(h.readyz, http.MethodGet, "/readyz", context.Background(), nil)
	if rec.Code != http.StatusServiceUnavailable || body["status"] != "not_ready" || body["error"] != "draining" {
		t.Fatalf("draining readyz = %d %v (want 503 not_ready/draining)", rec.Code, body)
	}
}

// TestServer_SetDrainingWiresToReadyz exercises the full wiring: SetDraining on
// the Server flips the flag the readyz handler reads through the shared pointer.
func TestServer_SetDrainingWiresToReadyz(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	s := &Server{mux: http.NewServeMux(), store: st, log: logger.New("error")}
	s.registerRoutes()

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-drain /readyz = %d", rec.Code)
	}

	s.SetDraining(true)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining /readyz = %d (want 503)", rec.Code)
	}
}

func TestGetConfig_RedactsAndShapes(t *testing.T) {
	h, _ := redisHandlers(t)
	rec, body := doReq(h.getConfig, http.MethodGet, "/api/config", context.Background(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("config = %d", rec.Code)
	}
	if body["listen"] != ":8080" {
		t.Fatalf("listen missing: %v", body)
	}
	if _, ok := body["admin_secret"]; ok {
		t.Fatal("config leaked admin_secret")
	}
	if got, _ := body["routes_count"].(float64); got != 1 {
		t.Fatalf("routes_count = %v, want 1", body["routes_count"])
	}
}

// TestGetConfig_RoutesCountTenantScoped is a regression test: routes_count
// used to be len(h.cfg.Routes) unconditionally — the WHOLE deployment's
// route count across every tenant, unfiltered, unlike getRoutes (which
// already scopes the route list itself). A tenant B admin could learn
// tenant A's deployment scale/topology from a field that should mirror
// getRoutes' own scoping. Only a super-admin sees the true total.
func TestGetConfig_RoutesCountTenantScoped(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.Routes = []config.RouteConfig{
		{Path: "/acme/", TenantID: "acme", Upstreams: []string{"http://acme-internal"}},
		{Path: "/globex/", TenantID: "globex", Upstreams: []string{"http://globex-internal"}},
		{Path: "/shared/", Upstreams: []string{"http://shared"}}, // TenantID == "" (single-tenant style)
	}

	// acme viewer: own route + tenant-agnostic shared route = 2, not 3.
	rec, body := doReq(h.getConfig, http.MethodGet, "/api/config", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("config = %d", rec.Code)
	}
	if got, _ := body["routes_count"].(float64); got != 2 {
		t.Fatalf("acme session routes_count = %v, want 2 (acme's + shared, not globex's)", body["routes_count"])
	}

	// Super-admin sees the true total.
	rec, body = doReq(h.getConfig, http.MethodGet, "/api/config", ctxAs("acme", iam.RoleAdmin, true), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("config = %d", rec.Code)
	}
	if got, _ := body["routes_count"].(float64); got != 3 {
		t.Fatalf("super-admin routes_count = %v, want 3 (all routes)", body["routes_count"])
	}
}

func TestGetRoutes_OK(t *testing.T) {
	h, _ := redisHandlers(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	h.getRoutes(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("routes = %d", rec.Code)
	}
}

// TestGetRoutes_TenantScoped guards VULN H1: a non-super-admin session must
// only see its own tenant's routes (plus tenant-agnostic global ones), never
// another tenant's upstream/security config. Only a super-admin sees all.
func TestGetRoutes_TenantScoped(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.Routes = []config.RouteConfig{
		{Path: "/acme/", TenantID: "acme", Upstreams: []string{"http://acme-internal"}},
		{Path: "/globex/", TenantID: "globex", Upstreams: []string{"http://globex-internal"}},
		{Path: "/shared/", Upstreams: []string{"http://shared"}}, // TenantID == "" (single-tenant style)
	}

	// A viewer in "acme" must not see globex's route.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/routes", nil).WithContext(ctxAs("acme", iam.RoleViewer, false))
	h.getRoutes(rec, r)
	var got []config.RouteConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	paths := map[string]bool{}
	for _, rt := range got {
		paths[rt.Path] = true
	}
	if !paths["/acme/"] || !paths["/shared/"] {
		t.Fatalf("acme session should see its own + shared routes, got %v", paths)
	}
	if paths["/globex/"] {
		t.Fatal("acme session must NOT see globex's route (cross-tenant leak)")
	}

	// A super-admin sees everything.
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/routes", nil).WithContext(ctxAs("acme", iam.RoleAdmin, true))
	h.getRoutes(rec, r)
	got = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("super-admin should see all 3 routes, got %d", len(got))
	}
}

func TestGetMetrics_ReflectsCounters(t *testing.T) {
	h, _ := redisHandlers(t)
	ctx := context.Background()
	h.store.IncrMetric(ctx, "blocked_waf")
	h.store.IncrMetric(ctx, "blocked_waf")
	rec, body := doReq(h.getMetrics, http.MethodGet, "/api/metrics", ctx, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics = %d", rec.Code)
	}
	if got, _ := body["blocked_waf"].(float64); got != 2 {
		t.Fatalf("blocked_waf = %v, want 2", body["blocked_waf"])
	}
}

func TestGetInventory_Empty(t *testing.T) {
	h, _ := redisHandlers(t)
	rec, body := doReq(h.getInventory, http.MethodGet, "/api/inventory", context.Background(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory = %d", rec.Code)
	}
	if got, _ := body["count"].(float64); got != 0 {
		t.Fatalf("count = %v, want 0", body["count"])
	}
}

func TestGetBlockLog_Empty(t *testing.T) {
	h, _ := redisHandlers(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/block-log", nil)
	h.getBlockLog(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("block-log = %d", rec.Code)
	}
}

// ── IP management round-trip + RBAC ──────────────────────────────────────────

func TestBlockIP_RoundTrip(t *testing.T) {
	h, _ := redisHandlers(t)
	admin := ctxAs("default", iam.RoleAdmin, false)

	// Block.
	rec, _ := doReq(h.blockIPHandler, http.MethodPost, "/api/blocked-ips", admin,
		map[string]any{"ip": "9.9.9.9", "reason": "test"})
	if rec.Code != http.StatusOK {
		t.Fatalf("block = %d", rec.Code)
	}
	// List shows it.
	rec, body := doReq(h.getBlockedIPs, http.MethodGet, "/api/blocked-ips", admin, nil)
	if rec.Code != http.StatusOK || body["count"].(float64) != 1 {
		t.Fatalf("list after block = %d %v", rec.Code, body)
	}
	// Unblock.
	r := httptest.NewRequest(http.MethodDelete, "/api/blocked-ips/9.9.9.9", nil)
	r = r.WithContext(admin)
	r.SetPathValue("ip", "9.9.9.9")
	rec2 := httptest.NewRecorder()
	h.unblockIPHandler(rec2, r)
	if rec2.Code != http.StatusOK {
		t.Fatalf("unblock = %d", rec2.Code)
	}
	if blocked, _ := h.store.IsIPBlocked(context.Background(), "9.9.9.9"); blocked {
		t.Fatal("IP still blocked after unblock")
	}
}

func TestBlockIP_InvalidIP(t *testing.T) {
	h, _ := redisHandlers(t)
	admin := ctxAs("default", iam.RoleAdmin, false)
	rec, _ := doReq(h.blockIPHandler, http.MethodPost, "/api/blocked-ips", admin,
		map[string]any{"ip": "not-an-ip"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid ip = %d, want 400", rec.Code)
	}
}

func TestBlockIP_RejectsLoopbackAndUnspecified(t *testing.T) {
	h, _ := redisHandlers(t)
	admin := ctxAs("default", iam.RoleAdmin, false)
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "::1", "169.254.1.1"} {
		rec, _ := doReq(h.blockIPHandler, http.MethodPost, "/api/blocked-ips", admin,
			map[string]any{"ip": ip})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("block %q = %d, want 400", ip, rec.Code)
		}
	}
}

func TestBlockIP_ViewerForbidden(t *testing.T) {
	h, _ := redisHandlers(t)
	// Even with outer AdminAuth disabled, the in-handler requireMutator still
	// rejects a viewer-role session (defence in depth via the role in context).
	viewer := ctxAs("default", iam.RoleViewer, false)
	rec, _ := doReq(h.blockIPHandler, http.MethodPost, "/api/blocked-ips", viewer,
		map[string]any{"ip": "9.9.9.9"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer block = %d, want 403", rec.Code)
	}
}

// ── JWT revocation ───────────────────────────────────────────────────────────

func TestRevokeJWT_RoundTrip(t *testing.T) {
	h, _ := redisHandlers(t)
	admin := ctxAs("default", iam.RoleAdmin, false)
	rec, _ := doReq(h.revokeJWT, http.MethodPost, "/api/jwt/revoke", admin,
		map[string]any{"jti": "abc-123", "ttl_seconds": 60})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	revoked, _ := h.store.IsJTIRevoked(context.Background(), "abc-123")
	if !revoked {
		t.Fatal("jti not revoked in store")
	}
}

func TestRevokeJWT_MissingJTI(t *testing.T) {
	h, _ := redisHandlers(t)
	admin := ctxAs("default", iam.RoleAdmin, false)
	rec, _ := doReq(h.revokeJWT, http.MethodPost, "/api/jwt/revoke", admin,
		map[string]any{"ttl_seconds": 60})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing jti = %d, want 400", rec.Code)
	}
}

func TestRevokeJWT_RejectsNegativeTTL(t *testing.T) {
	h, _ := redisHandlers(t)
	admin := ctxAs("default", iam.RoleAdmin, false)
	rec, _ := doReq(h.revokeJWT, http.MethodPost, "/api/jwt/revoke", admin,
		map[string]any{"jti": "abc-123", "ttl_seconds": -1})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("negative ttl_seconds = %d, want 400", rec.Code)
	}
	if revoked, _ := h.store.IsJTIRevoked(context.Background(), "abc-123"); revoked {
		t.Fatal("jti must not be revoked when ttl_seconds is rejected")
	}
}

// GET /api/block-log used to hardcode 100 entries and ignore ?limit entirely,
// so anything older than the last hundred events was unreachable through the
// API even though the ring buffer keeps a thousand. These pin the parameter.

func TestBlockLog_HonoursLimit(t *testing.T) {
	h, _ := redisHandlers(t)
	for i := 0; i < 12; i++ {
		h.store.PushForensic(context.Background(), store.ForensicEntry{
			Timestamp: time.Now().UTC(), IP: "1.1.1.1", Path: "/x",
			Method: "GET", Reason: "waf_block", Code: 403,
		})
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/block-log?limit=5", nil)
	h.getBlockLog(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []store.ForensicEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("entries = %d, want 5 (the requested limit must be honoured)", len(got))
	}
}

func TestBlockLog_RejectsInvalidLimit(t *testing.T) {
	h, _ := redisHandlers(t)
	for _, bad := range []string{"0", "-3", "abc"} {
		rec := httptest.NewRecorder()
		h.getBlockLog(rec, httptest.NewRequest(http.MethodGet, "/api/block-log?limit="+bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%q: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestBlockLog_CapsLimitAtRingBufferSize(t *testing.T) {
	// Asking for more than the buffer holds must not error — it just cannot
	// return more than exists.
	h, _ := redisHandlers(t)
	h.store.PushForensic(context.Background(), store.ForensicEntry{
		Timestamp: time.Now().UTC(), IP: "1.1.1.1", Path: "/x",
		Method: "GET", Reason: "waf_block", Code: 403,
	})
	rec := httptest.NewRecorder()
	h.getBlockLog(rec, httptest.NewRequest(http.MethodGet, "/api/block-log?limit=999999", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
