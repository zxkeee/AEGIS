package middleware

import (
	"net/http"

	"api-gateway/internal/config"
)

// BehaviorAnalysis calculates a risk score for each request and blocks high-risk IPs.
func BehaviorAnalysis(cfg config.BehaviorConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)

			// Wrap response to capture status code
			sw := &statusWriter{ResponseWriter: w, status: 200}

			next.ServeHTTP(sw, r)

			// Record request for scoring (post-processing)
			st.RecordRequest(r.Context(), ip, r.URL.Path, sw.status)

			// Calculate risk score
			score := st.CalcBehaviorScore(r.Context(), ip, cfg.ScoreThreshold)

			if score >= cfg.ScoreThreshold {
				// Auto-ban after repeated high scores
				count, _ := st.IncrAutoBanCounter(r.Context(), ip)
				if count >= 3 {
					st.BlockIP(r.Context(), ip) //nolint:errcheck
					log.Warn("behavior: auto-banned IP", map[string]any{
						"ip":    ip,
						"score": score,
					})
					st.IncrMetric(r.Context(), "behavior_autoban")
				}
			}
		})
	}
}
