package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"api-gateway/internal/alert"
	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/forensic"
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
	// forensic is the durable (PostgreSQL) security-event record. nil when
	// forensic_dsn is unset, in which case only the Redis ring is available.
	forensic *forensic.PGSink
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
	// ready caches the readiness Redis check — see readinessTTL.
	ready readinessCache
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

// readinessTTL bounds how often /readyz actually touches Redis.
//
// The probe endpoints are exempt from the admin plane's per-IP rate limit
// (gateway.BuildAdminChain explains why: a shared limiter lets an
// unauthenticated caller starve the readiness probe and get the instance pulled
// from rotation). Exempt and uncached, though, /readyz would be an
// unauthenticated Redis-ping amplifier. Caching the result makes a flood cost at
// most one PING per second while staying far fresher than any probe interval —
// a real outage is still reported within a second.
// A var, not a const, so a test can shrink it and still exercise expiry.
var readinessTTL = time.Second

// readinessCache holds the most recent readiness check and when it was taken.
type readinessCache struct {
	mu      sync.Mutex
	checked time.Time
	err     error
}

// ping returns the readiness of the backing store, reusing a result younger than
// readinessTTL. The lock is held across the store call so a burst collapses onto
// one in-flight PING rather than one per caller.
func (h *handlers) ping(ctx context.Context) error {
	h.ready.mu.Lock()
	defer h.ready.mu.Unlock()
	if time.Since(h.ready.checked) < readinessTTL {
		return h.ready.err
	}
	h.ready.err = h.store.Ping(ctx)
	h.ready.checked = time.Now()
	return h.ready.err
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
	if err := h.ping(r.Context()); err != nil {
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

// blockLogDefaultLimit / blockLogMaxLimit bound GET /api/block-log.
//
// The limit used to be hardcoded at 100 with the query parameter ignored
// entirely, so on a busy gateway every event older than the last hundred was
// unreachable through the API even though the Redis ring buffer keeps a
// thousand. That is not a cosmetic gap: security events are exactly what an
// operator pages back through after an incident, and a silently-truncated
// response looks identical to "nothing else happened" (audit finding,
// 2026-08-28 — found when an entire class of BFLA detections vanished from an
// export because a later burst had pushed them out of the window).
//
// The ceiling matches the ring buffer's own size; asking for more cannot return
// more, and letting an unbounded value through would just build a large
// response for no extra data.
const (
	blockLogDefaultLimit = 100
	blockLogMaxLimit     = 1000
)

func (h *handlers) getBlockLog(w http.ResponseWriter, r *http.Request) {
	limit := int64(blockLogDefaultLimit)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "limit must be a positive integer",
			})
			return
		}
		limit = min(int64(n), int64(blockLogMaxLimit))
	}

	// Optional window and filters. They only mean anything against the durable
	// record; the Redis ring below cannot answer "what happened in Q3".
	from, to, perr := parseTimeWindow(r)
	if perr != nil {
		writeError(w, http.StatusBadRequest, perr.Error())
		return
	}
	ip := r.URL.Query().Get("ip")
	reason := r.URL.Query().Get("reason")

	// The durable record when PostgreSQL is configured. Until now nothing read
	// it: events were written to forensic_logs and the API served the Redis ring
	// instead, so the evidence trail existed and was unreachable.
	if h.forensic != nil {
		entries, err := h.forensic.QueryLogs(r.Context(), forensic.LogFilter{
			TenantID: tenant.From(r.Context()),
			Limit:    int(limit), IP: ip, Reason: reason, From: from, To: to,
		})
		if err != nil {
			h.writeStoreError(w, "admin: block log query failed", "failed to fetch block log", err)
			return
		}
		// The body stays a bare array: the console reads it that way, and this
		// change is about reaching the durable record, not reshaping the API.
		// Which store answered — and therefore whether the result is the record
		// or a recent slice of it — rides in headers, so a caller can tell them
		// apart without parsing a new envelope.
		w.Header().Set("X-Evidence-Source", "postgresql")
		w.Header().Set("X-Evidence-Complete", "true")
		if !from.IsZero() {
			w.Header().Set("X-Evidence-From", from.UTC().Format(time.RFC3339))
		}
		if !to.IsZero() {
			w.Header().Set("X-Evidence-To", to.UTC().Format(time.RFC3339))
		}
		writeJSON(w, http.StatusOK, entries)
		return
	}

	// No durable store. The ring holds only the most recent entries and is lost
	// with Redis, so say which store answered rather than let a caller mistake a
	// truncated view for the record.
	if !from.IsZero() || !to.IsZero() || ip != "" || reason != "" {
		writeError(w, http.StatusBadRequest,
			"filtering the block log needs the durable store; set forensic_dsn (the Redis ring cannot be queried)")
		return
	}
	entries, err := h.store.GetForensicLog(r.Context(), limit)
	if err != nil {
		h.writeStoreError(w, "admin: block log fetch failed", "failed to fetch block log", err)
		return
	}
	// Explicitly not complete: the ring is capped and does not survive a Redis
	// restart. A caller that mistakes it for the record draws conclusions from a
	// truncated view.
	w.Header().Set("X-Evidence-Source", "redis-ring")
	w.Header().Set("X-Evidence-Complete", "false")
	writeJSON(w, http.StatusOK, entries)
}

// parseTimeWindow reads the optional from/to query parameters as RFC 3339.
// Both are inclusive; either may be omitted to leave that bound open.
func parseTimeWindow(r *http.Request) (from, to time.Time, err error) {
	parse := func(name string) (time.Time, error) {
		v := r.URL.Query().Get(name)
		if v == "" {
			return time.Time{}, nil
		}
		t, perr := time.Parse(time.RFC3339, v)
		if perr != nil {
			return time.Time{}, fmt.Errorf("%s must be an RFC 3339 timestamp, e.g. 2026-07-01T00:00:00Z", name)
		}
		return t, nil
	}
	if from, err = parse("from"); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if to, err = parse("to"); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		return time.Time{}, time.Time{}, errors.New("to must not be earlier than from")
	}
	return from, to, nil
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
