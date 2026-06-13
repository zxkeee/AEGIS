package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"api-gateway/internal/config"
)

// AdminAuth protects the management API using a static bearer secret.
//
// Public routes (no auth required):
//   - GET /          — dashboard HTML (static, no sensitive data; real auth is in JS)
//   - GET /health    — liveness probe for orchestrators
//   - GET /readyz    — readiness probe for orchestrators
//
// All /api/* routes require "Authorization: Bearer <AEGIS_ADMIN_SECRET>".
func AdminAuth(cfg config.GatewayConfig, log Logger, st Store) Middleware {
	secretBytes := []byte(cfg.AdminSecret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// admin_auth:false is only for local development — log a warning on every
			// request so operators notice it is enabled in non-dev environments.
			if !cfg.AdminAuth {
				log.Warn("admin_auth_disabled: request served without authentication",
					map[string]any{"path": r.URL.Path, "ip": RealIP(r)})
				next.ServeHTTP(w, r)
				return
			}

			// Probes and the dashboard HTML are intentionally public.
			// The dashboard is static HTML with a JS login form; no sensitive
			// data is embedded — all data loads via authenticated /api/* calls.
			if r.URL.Path == "/health" || r.URL.Path == "/readyz" || r.URL.Path == "/" {
				next.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				SecurityDeny(w, r, log, st, "admin_no_auth", RealIP(r), http.StatusUnauthorized, nil)
				return
			}

			token := strings.TrimPrefix(auth, "Bearer ")

			if subtle.ConstantTimeCompare([]byte(token), secretBytes) != 1 {
				SecurityDeny(w, r, log, st, "admin_bad_secret", RealIP(r), http.StatusForbidden, nil)
				return
			}

			// Audit log every successful admin API call.
			log.Info("admin_access", map[string]any{
				"path":   r.URL.Path,
				"method": r.Method,
				"ip":     RealIP(r),
			})

			next.ServeHTTP(w, r)
		})
	}
}
