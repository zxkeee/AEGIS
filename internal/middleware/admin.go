package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"
)

// Cookie and header names used for console session authentication.
const (
	SessionCookie = "aegis_session"
	CSRFCookie    = "aegis_csrf"
	CSRFHeader    = "X-CSRF-Token"
)

// AdminAuth protects the management API. Two authentication methods are accepted:
//
//   - Bearer token (`Authorization: Bearer <AEGIS_ADMIN_SECRET>`) for API/CLI
//     clients. Constant-time compared; no CSRF protection needed (not cookie-based).
//   - Session cookie (`aegis_session`) for the browser console, issued by
//     /api/login. The raw admin secret is never stored in the browser; the cookie
//     is HttpOnly so it cannot be read by JavaScript (mitigating token theft via
//     XSS). State-changing requests additionally require a matching CSRF token in
//     the X-CSRF-Token header (defence against cross-site request forgery).
//
// Public routes (no auth): GET /, /health, /readyz, and POST /api/login.
func AdminAuth(cfg config.GatewayConfig, log Logger, st adminStore, aud audit.Recorder) Middleware {
	secretBytes := []byte(cfg.AdminSecret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.AdminAuth {
				log.Warn("admin_auth_disabled: request served without authentication",
					map[string]any{"path": r.URL.Path, "ip": RealIP(r)})
				next.ServeHTTP(w, r)
				return
			}

			// Public endpoints: probes, the console shell + its static bundle, the
			// public bootstrap, the login route, and the OIDC SSO flow (the flow
			// itself IS the authentication). Everything else requires a session.
			switch r.URL.Path {
			case "/health", "/readyz", "/", "/api/console/env":
				next.ServeHTTP(w, r)
				return
			case "/api/login", "/api/auth/oidc/login", "/api/auth/oidc/callback":
				next.ServeHTTP(w, r)
				return
			}
			// The console's hashed bundle assets are public (they contain no data).
			// Use the segment-boundary matcher (not raw HasPrefix) so path
			// prefixing is uniform across the codebase and the lint invariant
			// stays strict.
			if config.PathHasPrefix(r.URL.Path, "/assets/") {
				next.ServeHTTP(w, r)
				return
			}

			// Method 1: bearer token (API/CLI). Bearer is the system bootstrap
			// credential: it is super-admin and is implicitly scoped to the
			// default tenant. Real per-tenant operators must use console login.
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				if subtle.ConstantTimeCompare([]byte(token), secretBytes) == 1 {
					ctx := tenant.With(r.Context(), tenant.Default)
					ctx = iam.WithRole(ctx, iam.RoleAdmin)
					ctx = iam.WithSuperAdmin(ctx, true)
					serveAndAudit(aud, next, w, r.WithContext(ctx), audit.Entry{
						TenantID: tenant.Default, ActorID: "bearer", ActorEmail: "bearer",
						Role: string(iam.RoleAdmin), SuperAdmin: true,
					})
					return
				}
				recordDeny(aud, r, "admin_bad_secret", http.StatusForbidden, audit.Entry{})
				SecurityDeny(w, r, log, st, "admin_bad_secret", RealIP(r), http.StatusForbidden, nil)
				return
			}

			// Method 2: session cookie (browser console).
			cookie, err := r.Cookie(SessionCookie)
			if err != nil || cookie.Value == "" {
				recordDeny(aud, r, "admin_no_auth", http.StatusUnauthorized, audit.Entry{})
				SecurityDeny(w, r, log, st, "admin_no_auth", RealIP(r), http.StatusUnauthorized, nil)
				return
			}
			sess, ok, verr := st.ValidateSession(r.Context(), cookie.Value)
			if verr != nil {
				log.Error("admin: session validation failed", map[string]any{"error": verr.Error()})
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}
			if !ok {
				recordDeny(aud, r, "admin_bad_session", http.StatusUnauthorized, audit.Entry{})
				SecurityDeny(w, r, log, st, "admin_bad_session", RealIP(r), http.StatusUnauthorized, nil)
				return
			}
			actor := audit.Entry{
				TenantID: sess.TenantID, ActorID: sess.UserID, ActorEmail: sess.Email,
				Role: string(sess.Role), SuperAdmin: sess.SuperAdmin,
			}
			// CSRF check on state-changing methods (double-submit bound to session).
			if isMutating(r.Method) {
				if subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(sess.CSRF)) != 1 {
					recordDeny(aud, r, "admin_csrf_failed", http.StatusForbidden, actor)
					SecurityDeny(w, r, log, st, "admin_csrf_failed", RealIP(r), http.StatusForbidden, nil)
					return
				}
				// RBAC: viewer may read but never mutate. Returning 403 (not 401)
				// signals "authenticated, but lacks permission".
				if !sess.Role.CanMutate() {
					recordDeny(aud, r, "admin_viewer_forbidden", http.StatusForbidden, actor)
					SecurityDeny(w, r, log, st, "admin_viewer_forbidden", RealIP(r), http.StatusForbidden,
						map[string]any{"role": string(sess.Role), "tenant": sess.TenantID})
					return
				}
			}

			// Thread the resolved tenant + role into the request context. The
			// session's tenant overrides anything TenantResolve may have set, so
			// admin reads/writes are always scoped to the operator's tenant.
			ctx := tenant.With(r.Context(), sess.TenantID)
			ctx = iam.WithRole(ctx, sess.Role)
			ctx = iam.WithSuperAdmin(ctx, sess.SuperAdmin)
			ctx = iam.WithUserID(ctx, sess.UserID)
			serveAndAudit(aud, next, w, r.WithContext(ctx), actor)
		})
	}
}

// serveAndAudit serves the request and, for state-changing methods, records a
// persistent audit entry with the final response status. Read (GET/HEAD)
// requests are not recorded to keep the audit log signal-rich; the application
// log still notes every access.
func serveAndAudit(aud audit.Recorder, next http.Handler, w http.ResponseWriter, r *http.Request, actor audit.Entry) {
	if aud == nil || !isMutating(r.Method) {
		next.ServeHTTP(w, r)
		return
	}
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	next.ServeHTTP(sw, r)
	actor.Action = "mutation"
	actor.Method = r.Method
	actor.Path = r.URL.Path
	actor.Status = sw.status
	actor.IP = RealIP(r)
	aud.Record(actor)
}

// recordDeny records an access-control rejection (best-effort). actor may be
// empty when the caller could not be identified (no/invalid credentials).
func recordDeny(aud audit.Recorder, r *http.Request, reason string, status int, actor audit.Entry) {
	if aud == nil {
		return
	}
	actor.Action = "denied:" + reason
	actor.Method = r.Method
	actor.Path = r.URL.Path
	actor.Status = status
	actor.IP = RealIP(r)
	aud.Record(actor)
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
