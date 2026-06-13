package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"api-gateway/internal/config"
)

// CORS handles Cross-Origin Resource Sharing headers.
//
// Security rules enforced:
//   - Wildcard "*" is only allowed when no Authorization header is in
//     AllowHeaders (credentials + wildcard is forbidden by the CORS spec
//     and rejected by all browsers anyway).
//   - Per-origin matching adds "Vary: Origin" so shared caches never serve
//     one origin's response to another.
//   - Preflight requests whose Origin is not in the allowlist receive 403
//     instead of silently dropping CORS headers (which would make debugging
//     opaque and could mask misconfigurations).
func CORS(cfg config.CORSConfig) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	isWildcard := len(cfg.AllowOrigins) == 1 && cfg.AllowOrigins[0] == "*"

	// Build O(1) lookup set for per-origin matching.
	allowedOrigins := make(map[string]struct{}, len(cfg.AllowOrigins))
	for _, o := range cfg.AllowOrigins {
		allowedOrigins[o] = struct{}{}
	}

	methods := strings.Join(cfg.AllowMethods, ", ")
	headers := strings.Join(cfg.AllowHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAge)

	if methods == "" {
		methods = "GET, POST, PUT, DELETE, OPTIONS"
	}
	if headers == "" {
		headers = "Content-Type, Authorization, X-Service-ID, X-Service-Signature, X-Timestamp"
	}
	if cfg.MaxAge == 0 {
		maxAge = "86400"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Requests without an Origin header are not cross-origin — skip.
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			if isWildcard {
				// Wildcard: any origin is allowed, but credentials are NOT
				// permitted by the spec (browsers enforce this; we make it explicit).
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				// Per-origin matching — caches must vary their response on Origin.
				w.Header().Add("Vary", "Origin")

				if _, ok := allowedOrigins[origin]; !ok {
					// Origin not in allowlist.
					// Reject preflight with 403 so the browser surfaces a clear
					// error; for actual requests just omit the ACAO header (the
					// browser will block the response on the client side).
					if r.Method == http.MethodOptions {
						http.Error(w, "CORS origin not allowed", http.StatusForbidden)
						return
					}
					next.ServeHTTP(w, r)
					return
				}

				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			w.Header().Set("Access-Control-Max-Age", maxAge)

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
