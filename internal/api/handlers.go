package api

import (
	"crypto/subtle"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"api-gateway/internal/alert"
	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/proxy"
	"api-gateway/internal/store"
	"api-gateway/internal/tenant"
)

type handlers struct {
	store   *store.Store
	log     *logger.Logger
	cfg     config.GatewayConfig
	gateway *proxy.Gateway
	alerts  *alert.Engine
	catalog *discovery.Catalog
	// specCat is the spec/drift surface of the catalog behind a narrow interface
	// so the spec handlers are testable with a fake (no PostgreSQL). It is left
	// nil when discovery is disabled; spec handlers then degrade to 503.
	specCat specOps
	users   *iam.Store   // optional: nil when forensic_dsn is unset
	audit   *audit.Store // optional: nil when forensic_dsn is unset
	// oidc is the SSO authenticator; nil when oidc is disabled or discovery
	// failed at startup. Behind an interface so the callback flow is testable.
	oidc OIDCAuthenticator
	// draining reflects lame-duck shutdown state; when set, readyz reports 503 so
	// upstreams drain the gateway before it stops accepting connections. May be
	// nil in unit tests that construct handlers directly.
	draining *atomic.Bool
	// licenseStatus points at the Server's atomic.Value holding the current
	// license.Status (set via Server.SetLicenseStatus on boot/hot-reload). May
	// be nil in unit tests that construct handlers directly; getLicense treats
	// that the same as "no status recorded yet".
	licenseStatus *atomic.Value
}

// auditCrossTenantRead records a super-admin GET that spans a tenant other
// than the operator's own (or spans every tenant). Regular mutating requests
// are already recorded by serveAndAudit; GETs are deliberately NOT recorded
// there to keep the audit log signal-rich, but a super-admin browsing another
// tenant's users/audit-trail/tenant list is exactly the "who looked at tenant
// B's data" question an auditor asks, so this narrow class of read is logged
// explicitly instead. h.audit is nil-safe (Store.Record no-ops on a nil
// receiver), so this is safe to call unconditionally.
func (h *handlers) auditCrossTenantRead(r *http.Request, action, targetTenant string) {
	h.audit.Record(audit.Entry{
		TenantID:   tenant.From(r.Context()),
		ActorID:    iam.UserID(r.Context()),
		Role:       string(iam.FromContext(r.Context())),
		SuperAdmin: true,
		Action:     action,
		Method:     r.Method,
		Path:       r.URL.Path,
		Status:     http.StatusOK,
		IP:         middleware.RealIP(r),
		Detail:     "target_tenant=" + targetTenant,
	})
}

// requireAuth is a defence-in-depth check called directly inside mutating
// handlers. It ensures state-changing operations are always authenticated,
// even if a future middleware refactor accidentally removes the outer check.
func (h *handlers) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if !h.cfg.AdminAuth {
		return true // auth disabled (dev mode), already warned at startup
	}
	// Method 1: bearer token (API/CLI).
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.cfg.AdminSecret)) == 1 {
			return true
		}
		writeError(w, http.StatusForbidden, "invalid credentials")
		return false
	}
	// Method 2: console session cookie (CSRF already enforced by AdminAuth).
	if c, err := r.Cookie(middleware.SessionCookie); err == nil && c.Value != "" {
		if _, ok, _ := h.store.ValidateSession(r.Context(), c.Value); ok {
			return true
		}
	}
	writeError(w, http.StatusUnauthorized, "authentication required")
	return false
}

// requireMutator additionally enforces the RBAC rule: viewer sessions cannot
// invoke state-changing handlers (the outer AdminAuth also enforces this, this
// is a belt-and-braces check inside the handler).
func (h *handlers) requireMutator(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireAuth(w, r) {
		return false
	}
	if !iam.FromContext(r.Context()).CanMutate() {
		writeError(w, http.StatusForbidden, "viewer role cannot perform this action")
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

// storeUnavailable reports whether err means the backing store (PostgreSQL or
// Redis) is unreachable, as opposed to a genuine query/logic error. A dependency
// outage should surface as 503 (retryable) rather than 500 (reads as a bug); a
// load balancer / client backs off on 503 but not on 500.
func storeUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		return true
	}
	s := strings.ToLower(err.Error())
	for _, sub := range []string{
		"connection refused", "connection reset", "no such host",
		"dial tcp", "broken pipe", "server closed the connection",
		"the database system is", "cannot connect", "i/o timeout",
		"connection timed out", "bad connection", "no connection",
	} {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// writeStoreError logs the internal error and picks the right status: 503 when
// the backing store is unreachable (retryable), else 500. The public message is
// unchanged; only the code varies so clients/LBs get the correct retry signal.
func (h *handlers) writeStoreError(w http.ResponseWriter, logMsg, publicMsg string, err error) {
	h.log.Error(logMsg, map[string]any{"error": err.Error()})
	if storeUnavailable(err) {
		writeError(w, http.StatusServiceUnavailable, publicMsg+" (backing store unavailable, retry shortly)")
		return
	}
	writeError(w, http.StatusInternalServerError, publicMsg)
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
	// Lame-duck: once shutdown starts, report not-ready so a load balancer stops
	// routing new traffic while in-flight requests drain on existing connections.
	if h.draining != nil && h.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"error":  "draining",
		})
		return
	}
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
		h.writeStoreError(w, "admin: metrics fetch failed", "failed to fetch metrics", err)
		return
	}
	writeJSON(w, http.StatusOK, metrics)
}

// ── Config ────────────────────────────────────────────────────────────────────

func (h *handlers) getConfig(w http.ResponseWriter, r *http.Request) {
	// Sanitize: never expose secrets. The "security" toggles below are
	// GLOBAL (security.* applies to every tenant unless a route overrides
	// it — ADR-001) and are not another tenant's data, so exposing them here
	// is intentional, unlike routes_count: an unfiltered len(h.cfg.Routes)
	// reveals the WHOLE deployment's route count across every tenant to any
	// authenticated caller — deployment topology/scale a tenant B operator
	// has no reason to learn about. Scoped the same way getRoutes already
	// scopes the route list itself (audit finding, 2026-08-22).
	routesCount := len(h.cfg.Routes)
	if !iam.IsSuperAdmin(r.Context()) {
		self := tenant.From(r.Context())
		routesCount = 0
		for _, rt := range h.cfg.Routes {
			if rt.TenantID == "" || rt.TenantID == self {
				routesCount++
			}
		}
	}
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
		"routes_count": routesCount,
	}
	writeJSON(w, http.StatusOK, safe)
}

// ── Routes ────────────────────────────────────────────────────────────────────

// getRoutes returns the caller's own route configuration. Unlike a single
// global route list, this is scoped by tenant — h.cfg.Routes spans every
// tenant on the deployment, and a route's Upstreams/WAF/DLP/RateLimit
// overrides are exactly the kind of internal topology a tenant B operator
// must not learn about tenant A. Only a super-admin sees the unfiltered list,
// mirroring listTenants/listUsers.
func (h *handlers) getRoutes(w http.ResponseWriter, r *http.Request) {
	if iam.IsSuperAdmin(r.Context()) {
		writeJSON(w, http.StatusOK, h.cfg.Routes)
		return
	}
	self := tenant.From(r.Context())
	owned := make([]config.RouteConfig, 0, len(h.cfg.Routes))
	for _, rt := range h.cfg.Routes {
		// Single-tenant deployments leave TenantID empty on every route; treat
		// that as "belongs to every tenant" rather than hiding it from everyone.
		if rt.TenantID == "" || rt.TenantID == self {
			owned = append(owned, rt)
		}
	}
	writeJSON(w, http.StatusOK, owned)
}

// ── Block Log (Forensics) ─────────────────────────────────────────────────────

func (h *handlers) getBlockLog(w http.ResponseWriter, r *http.Request) {
	entries, err := h.store.GetForensicLog(r.Context(), 100)
	if err != nil {
		h.writeStoreError(w, "admin: block log fetch failed", "failed to fetch block log", err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// ── API Inventory ─────────────────────────────────────────────────────────────

func (h *handlers) getInventory(w http.ResponseWriter, r *http.Request) {
	endpoints, err := h.store.GetInventory(r.Context())
	if err != nil {
		h.writeStoreError(w, "admin: inventory fetch failed", "failed to fetch inventory", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoints": endpoints,
		"count":     len(endpoints),
	})
}

// ── IP Management ─────────────────────────────────────────────────────────────

func (h *handlers) getBlockedIPs(w http.ResponseWriter, r *http.Request) {
	// Structured (source + TTL) so an operator can tell a deliberate admin
	// block from a still-live, self-expiring auto-ban before unblocking —
	// see store.BlockedIPInfo and unblockIPHandler's ?source= param.
	ips, err := h.store.GetBlockedIPDetails(r.Context())
	if err != nil {
		h.writeStoreError(w, "admin: blocked IPs fetch failed", "failed to fetch blocked IPs", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": ips, "count": len(ips)})
}

func (h *handlers) blockIPHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireMutator(w, r) {
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
	parsed := net.ParseIP(req.IP)
	if req.IP == "" || parsed == nil {
		writeError(w, http.StatusBadRequest, "valid IP address is required")
		return
	}
	if isUnblockableIP(parsed) {
		writeError(w, http.StatusBadRequest, "loopback, unspecified, and link-local addresses cannot be blocked")
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
	if !h.requireMutator(w, r) {
		return
	}
	ip := r.PathValue("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "valid IP address is required")
		return
	}
	// Optional ?source=manual|auto to lift just one kind of block, leaving the
	// other in place — e.g. clearing a live auto-ban without discarding a
	// deliberate admin block on the same IP. Omitted/"both" clears everything,
	// matching the previous (source-blind) behaviour.
	source := r.URL.Query().Get("source")
	switch source {
	case "", "manual", "auto", "both":
	default:
		writeError(w, http.StatusBadRequest, `source must be "manual", "auto", or omitted`)
		return
	}

	if err := h.store.UnblockIP(r.Context(), ip, source); err != nil {
		h.log.Error("admin: unblock IP failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to unblock IP")
		return
	}

	h.log.Info("ip_unblocked", map[string]any{"ip": ip})
	writeJSON(w, http.StatusOK, map[string]string{"message": "IP unblocked", "ip": ip})
}

// isUnblockableIP rejects addresses that would only cause self-inflicted
// disruption if blocked: loopback, unspecified, and link-local — none of
// which identify a real remote attacker.
func isUnblockableIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// ── JWT Revocation ────────────────────────────────────────────────────────────

func (h *handlers) revokeJWT(w http.ResponseWriter, r *http.Request) {
	if !h.requireMutator(w, r) {
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
	if req.TTLSeconds < 0 {
		writeError(w, http.StatusBadRequest, "ttl_seconds must not be negative")
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
