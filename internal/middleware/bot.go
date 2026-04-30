package middleware

import (
	"net/http"

	"api-gateway/internal/config"
)

// BotProtection detects and blocks automated traffic using JA3 fingerprinting.
func BotProtection(cfg config.BotConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	// Build blocked JA3 lookup set
	blocked := make(map[string]bool, len(cfg.BlockedJA3))
	for _, ja3 := range cfg.BlockedJA3 {
		blocked[ja3] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)

			// Check JA3 fingerprint (extracted by TLS layer)
			ja3 := r.Header.Get("X-JA3-Fingerprint")
			if ja3 != "" {
				if blocked[ja3] {
					log.BlockEvent("bot_ja3_blocked", ip, r.URL.Path, r.Method, map[string]any{
						"ja3": ja3,
					})
					st.IncrMetric(r.Context(), "bot_ja3_blocked")
					http.Error(w, "Access Denied (Bot Detected)", http.StatusForbidden)
					return
				}

				// JA3 Consistency Check: if an IP uses multiple different fingerprints,
				// it indicates a bot farm or proxy rotator
				isInconsistent, _ := st.CheckJA3Consistency(r.Context(), ip, ja3)
				if isInconsistent {
					log.Warn("bot_detection: JA3 inconsistency detected", map[string]any{
						"ip":  ip,
						"ja3": ja3,
					})
					st.IncrMetric(r.Context(), "bot_ja3_inconsistent")
					st.IncrBehaviorScore(r.Context(), ip, 20) // Add 20 risk points
				}

				r.Header.Set("X-JA3-Fingerprint", ja3)
			}

			// Basic bot detection via User-Agent
			ua := r.Header.Get("User-Agent")
			if ua == "" {
				st.IncrBehaviorScore(r.Context(), ip, 10)
				st.IncrMetric(r.Context(), "bot_empty_ua")
			}

			next.ServeHTTP(w, r)
		})
	}
}
