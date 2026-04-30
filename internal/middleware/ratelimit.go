package middleware

import (
	"fmt"
	"net/http"

	"api-gateway/internal/config"
)

// RateLimit enforces sliding-window rate limiting per client IP.
func RateLimit(cfg config.RateLimitConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)
			count, err := st.IncrRate(r.Context(), ip, cfg.Window)
			if err != nil {
				log.Error("rate_limit: redis error", map[string]any{"error": err.Error()})
				next.ServeHTTP(w, r)
				return
			}

			if count > int64(cfg.Requests) {
				SecurityDeny(w, r, log, st, "rate_limit_exceeded", ip, http.StatusTooManyRequests,
					map[string]any{"count": count, "limit": cfg.Requests})
				return
			}

			// FIX BUG-2: Use fmt.Sprintf instead of http.StatusText for numeric headers
			remaining := int64(cfg.Requests) - count
			if remaining < 0 {
				remaining = 0
			}
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.Requests))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

			next.ServeHTTP(w, r)
		})
	}
}
