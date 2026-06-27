package middleware

import (
	"fmt"
	"net/http"

	"api-gateway/internal/config"
)

// RateLimit enforces sliding-window rate limiting per client IP for a single,
// static configuration. scope namespaces the Redis counter so independent
// limiters (e.g. the admin-plane 5/s limit and the gateway 100/60s limit) never
// share a bucket for the same IP — previously both wrote gw:t:<tenant>:rate:<ip>,
// so whichever incremented first set the window TTL and both behaved wrongly.
func RateLimit(cfg config.RateLimitConfig, scope string, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)
			if applyRateLimit(w, r, cfg, rateKey(scope, "", cfg, ip), log, st) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// RouteRateLimit is the gateway data-plane limiter. It resolves the effective
// rate-limit config per request path (global merged with per-route overrides) so
// a route can raise/lower its own requests/window or disable limiting entirely.
// resolve returns the effective config, a stable route key (for counter
// isolation between routes), and whether limiting applies to the path.
func RouteRateLimit(resolve func(path string) (cfg config.RateLimitConfig, routeKey string, enabled bool), log Logger, st Store) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg, routeKey, enabled := resolve(r.URL.Path)
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}
			ip := RealIP(r)
			if applyRateLimit(w, r, cfg, rateKey("gw", routeKey, cfg, ip), log, st) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// rateKey builds the Redis counter key. It embeds scope, an optional per-route
// discriminator, and the window length so distinct limiters/routes/windows for
// the same IP get distinct fixed-window buckets.
func rateKey(scope, routeKey string, cfg config.RateLimitConfig, ip string) string {
	secs := int(cfg.Window.Seconds())
	if secs < 1 {
		secs = 1
	}
	if routeKey != "" {
		return fmt.Sprintf("%s:%s:%d:%s", scope, routeKey, secs, ip)
	}
	return fmt.Sprintf("%s:%d:%s", scope, secs, ip)
}

// applyRateLimit performs one increment-and-check against the store, writing the
// 429 (or fail-closed 503) itself and returning false when the request must be
// stopped. It returns true when the caller should continue the chain.
func applyRateLimit(w http.ResponseWriter, r *http.Request, cfg config.RateLimitConfig, key string, log Logger, st Store) bool {
	ip := RealIP(r)
	count, err := st.IncrRate(r.Context(), key, cfg.Window)
	if err != nil {
		log.Error("rate_limit: redis error", map[string]any{
			"error":       err.Error(),
			"fail_closed": cfg.FailClosed,
		})
		if cfg.FailClosed {
			// High-assurance mode: a backing-store outage must not silently
			// disable enforcement, so deny rather than pass through.
			SecurityDeny(w, r, log, st, "rate_limit_store_unavailable", ip,
				http.StatusServiceUnavailable, nil)
			return false
		}
		// Default: fail open to preserve availability.
		return true
	}

	if count > int64(cfg.Requests) {
		SecurityDeny(w, r, log, st, "rate_limit_exceeded", ip, http.StatusTooManyRequests,
			map[string]any{"count": count, "limit": cfg.Requests})
		return false
	}

	// FIX BUG-2: Use fmt.Sprintf instead of http.StatusText for numeric headers
	remaining := int64(cfg.Requests) - count
	if remaining < 0 {
		remaining = 0
	}
	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.Requests))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
	return true
}
