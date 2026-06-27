package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestGetRoutes_OK(t *testing.T) {
	h, _ := redisHandlers(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	h.getRoutes(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("routes = %d", rec.Code)
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
