package middleware

import (
	"net/http"
	"strings"

	"api-gateway/internal/config"
)

// CORS handles Cross-Origin Resource Sharing headers.
func CORS(cfg config.CORSConfig) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	origins := strings.Join(cfg.AllowOrigins, ", ")
	methods := strings.Join(cfg.AllowMethods, ", ")
	headers := strings.Join(cfg.AllowHeaders, ", ")

	if methods == "" {
		methods = "GET, POST, PUT, DELETE, OPTIONS"
	}
	if headers == "" {
		headers = "Content-Type, Authorization, X-Service-ID, X-Service-Signature, X-Timestamp"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			if origins == "" || origins == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" {
				for _, allowed := range cfg.AllowOrigins {
					if origin == allowed {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}

			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			w.Header().Set("Access-Control-Max-Age", "86400")

			// Handle preflight
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
