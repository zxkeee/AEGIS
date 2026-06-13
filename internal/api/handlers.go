package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"api-gateway/internal/alert"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
	"api-gateway/internal/proxy"
	"api-gateway/internal/store"
)

type handlers struct {
	store   *store.Store
	log     *logger.Logger
	cfg     config.GatewayConfig
	gateway *proxy.Gateway
	alerts  *alert.Engine
	catalog *discovery.Catalog
}

// requireAuth is a defence-in-depth check called directly inside mutating
// handlers. It ensures state-changing operations are always authenticated,
// even if a future middleware refactor accidentally removes the outer check.
func (h *handlers) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if !h.cfg.AdminAuth {
		return true // auth disabled (dev mode), already warned at startup
	}
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(token), []byte(h.cfg.AdminSecret)) != 1 {
		writeError(w, http.StatusForbidden, "invalid credentials")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

// writeError returns a safe error message without internal details.
// FIX SEC-3: Internal error details never leak to clients.
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// decodeJSON decodes a JSON body with a size limit.
// FIX SEC-4: Prevents OOM via oversized request bodies.
func decodeJSON(r *http.Request, v any) error {
	// Limit request body to 1MB
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// ── Health ────────────────────────────────────────────────────────────────────

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "healthy",
		"version": "1.0.0",
		"ts":      time.Now().UTC().Format(time.RFC3339),
	})
}

// ARCH-11: Readiness probe — checks Redis connectivity
func (h *handlers) readyz(w http.ResponseWriter, r *http.Request) {
	if err := h.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"error":  "redis_unavailable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
		"ts":     time.Now().UTC().Format(time.RFC3339),
	})
}

// ── Metrics ───────────────────────────────────────────────────────────────────

func (h *handlers) getMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.store.GetMetrics(r.Context())
	if err != nil {
		h.log.Error("admin: metrics fetch failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch metrics")
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

// ── Config ────────────────────────────────────────────────────────────────────

func (h *handlers) getConfig(w http.ResponseWriter, r *http.Request) {
	// Sanitize: never expose secrets
	safe := map[string]any{
		"listen":       h.cfg.Listen,
		"admin_listen": h.cfg.AdminListen,
		"admin_auth":   h.cfg.AdminAuth,
		"tls_enabled":  h.cfg.TLS.Enabled,
		"security": map[string]any{
			"rate_limit":    h.cfg.Security.RateLimit,
			"waf_enabled":   h.cfg.Security.WAF.Enabled,
			"bot_enabled":   h.cfg.Security.Bot.Enabled,
			"behavior":      h.cfg.Security.Behavior,
			"ip_guard":      h.cfg.Security.IPGuard.Enabled,
			"dlp_enabled":   h.cfg.Security.DLP.Enabled,
			"cors_enabled":  h.cfg.Security.CORS.Enabled,
			"challenge":     h.cfg.Security.Challenge.Enabled,
			"api_inventory": h.cfg.Security.Inventory.Enabled,
			"threat_feed":   h.cfg.Security.ThreatFeed.Enabled,
		},
		"routes_count": len(h.cfg.Routes),
	}
	writeJSON(w, http.StatusOK, safe)
}

// ── Routes ────────────────────────────────────────────────────────────────────

func (h *handlers) getRoutes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.cfg.Routes)
}

// ── Block Log (Forensics) ─────────────────────────────────────────────────────

func (h *handlers) getBlockLog(w http.ResponseWriter, r *http.Request) {
	entries, err := h.store.GetForensicLog(r.Context(), 100)
	if err != nil {
		h.log.Error("admin: block log fetch failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch block log")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// ── API Inventory ─────────────────────────────────────────────────────────────

func (h *handlers) getInventory(w http.ResponseWriter, r *http.Request) {
	endpoints, err := h.store.GetInventory(r.Context())
	if err != nil {
		h.log.Error("admin: inventory fetch failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch inventory")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoints": endpoints,
		"count":     len(endpoints),
	})
}

// ── IP Management ─────────────────────────────────────────────────────────────

func (h *handlers) getBlockedIPs(w http.ResponseWriter, r *http.Request) {
	ips, err := h.store.GetBlockedIPs(r.Context())
	if err != nil {
		h.log.Error("admin: blocked IPs fetch failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch blocked IPs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": ips, "count": len(ips)})
}

func (h *handlers) blockIPHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate IP format
	if req.IP == "" || net.ParseIP(req.IP) == nil {
		writeError(w, http.StatusBadRequest, "valid IP address is required")
		return
	}

	if err := h.store.BlockIP(r.Context(), req.IP); err != nil {
		h.log.Error("admin: block IP failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to block IP")
		return
	}

	h.log.Info("ip_blocked_manual", map[string]any{"ip": req.IP, "reason": req.Reason})
	writeJSON(w, http.StatusOK, map[string]string{"message": "IP blocked", "ip": req.IP})
}

func (h *handlers) unblockIPHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	ip := r.PathValue("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "valid IP address is required")
		return
	}

	if err := h.store.UnblockIP(r.Context(), ip); err != nil {
		h.log.Error("admin: unblock IP failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to unblock IP")
		return
	}

	h.log.Info("ip_unblocked", map[string]any{"ip": ip})
	writeJSON(w, http.StatusOK, map[string]string{"message": "IP unblocked", "ip": ip})
}

// ── JWT Revocation ────────────────────────────────────────────────────────────

func (h *handlers) revokeJWT(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	var req struct {
		JTI        string `json:"jti"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		if err == io.EOF {
			writeError(w, http.StatusBadRequest, "request body is required")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.JTI == "" {
		writeError(w, http.StatusBadRequest, "jti is required")
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour // Default 24h
	}
	// Cap TTL to prevent indefinite revocations
	if ttl > 30*24*time.Hour {
		ttl = 30 * 24 * time.Hour
	}

	if err := h.store.RevokeJTI(r.Context(), req.JTI, ttl); err != nil {
		h.log.Error("admin: JWT revoke failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}

	h.log.Info("jwt_revoked", map[string]any{"jti": req.JTI, "ttl": ttl.String()})
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "JWT revoked",
		"jti":     req.JTI,
		"expires": time.Now().Add(ttl).UTC().Format(time.RFC3339),
	})
}
