package middleware

import (
	"net/http"

	"api-gateway/internal/config"
)

// IPGuard enforces IP whitelist/blacklist rules.
func IPGuard(cfg config.IPGuardConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	whiteset := make(map[string]bool, len(cfg.Whitelist))
	for _, ip := range cfg.Whitelist {
		whiteset[ip] = true
	}
	blackset := make(map[string]bool, len(cfg.Blacklist))
	for _, ip := range cfg.Blacklist {
		blackset[ip] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)

			// Always allow whitelisted IPs
			if len(whiteset) > 0 && whiteset[ip] {
				next.ServeHTTP(w, r)
				return
			}

			// Check static blacklist
			if blackset[ip] {
				SecurityDeny(w, r, log, st, "ip_blacklisted", ip, http.StatusForbidden, nil)
				return
			}

			// Check dynamic blacklist (Redis)
			blocked, err := st.IsIPBlocked(r.Context(), ip)
			if err != nil {
				log.Error("ip_guard: redis error", map[string]any{"error": err.Error()})
			}
			if blocked {
				SecurityDeny(w, r, log, st, "ip_blocked_dynamic", ip, http.StatusForbidden, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
