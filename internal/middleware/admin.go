package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"api-gateway/internal/config"
)

// AdminAuth protects the management API using a static secret from config.
func AdminAuth(cfg config.GatewayConfig, log Logger, st Store) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.AdminAuth {
				next.ServeHTTP(w, r)
				return
			}

			// Allow health, readiness probes, and dashboard without auth
			if r.URL.Path == "/health" || r.URL.Path == "/readyz" || r.URL.Path == "/" {
				next.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				SecurityDeny(w, r, log, st, "admin_no_auth", RealIP(r), http.StatusForbidden, nil)
				return
			}

			token := strings.TrimPrefix(auth, "Bearer ")

			// FIX BUG-7: Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.AdminSecret)) != 1 {
				SecurityDeny(w, r, log, st, "admin_bad_secret", RealIP(r), http.StatusForbidden, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
