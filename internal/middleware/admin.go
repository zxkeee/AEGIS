package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"api-gateway/internal/config"
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
func AdminAuth(cfg config.GatewayConfig, log Logger, st Store) Middleware {
	secretBytes := []byte(cfg.AdminSecret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.AdminAuth {
				log.Warn("admin_auth_disabled: request served without authentication",
					map[string]any{"path": r.URL.Path, "ip": RealIP(r)})
				next.ServeHTTP(w, r)
				return
			}

			// Public endpoints: probes, the dashboard shell, and the login route.
			switch r.URL.Path {
			case "/health", "/readyz", "/":
				next.ServeHTTP(w, r)
				return
			case "/api/login":
				next.ServeHTTP(w, r)
				return
			}

			// Method 1: bearer token (API/CLI).
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				if subtle.ConstantTimeCompare([]byte(token), secretBytes) == 1 {
					auditAdmin(log, r)
					next.ServeHTTP(w, r)
					return
				}
				SecurityDeny(w, r, log, st, "admin_bad_secret", RealIP(r), http.StatusForbidden, nil)
				return
			}

			// Method 2: session cookie (browser console).
			cookie, err := r.Cookie(SessionCookie)
			if err != nil || cookie.Value == "" {
				SecurityDeny(w, r, log, st, "admin_no_auth", RealIP(r), http.StatusUnauthorized, nil)
				return
			}
			csrf, ok, verr := st.ValidateSession(r.Context(), cookie.Value)
			if verr != nil {
				log.Error("admin: session validation failed", map[string]any{"error": verr.Error()})
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}
			if !ok {
				SecurityDeny(w, r, log, st, "admin_bad_session", RealIP(r), http.StatusUnauthorized, nil)
				return
			}
			// CSRF check on state-changing methods (double-submit bound to session).
			if isMutating(r.Method) {
				if subtle.ConstantTimeCompare([]byte(r.Header.Get(CSRFHeader)), []byte(csrf)) != 1 {
					SecurityDeny(w, r, log, st, "admin_csrf_failed", RealIP(r), http.StatusForbidden, nil)
					return
				}
			}

			auditAdmin(log, r)
			next.ServeHTTP(w, r)
		})
	}
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func auditAdmin(log Logger, r *http.Request) {
	log.Info("admin_access", map[string]any{
		"path":   r.URL.Path,
		"method": r.Method,
		"ip":     RealIP(r),
	})
}
