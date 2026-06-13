package middleware

import (
	"net/http"

	"api-gateway/internal/config"
)

// BehaviorAnalysis calculates a risk score for each request and blocks high-risk IPs.
//
// Flow (preventive, not reactive):
//  1. Score is calculated from the IP's PRIOR request history before the request is served.
//  2. If score >= threshold the request is blocked immediately.
//  3. After the request, metrics are recorded so the next request sees updated data.
//
// This means an IP that has built up a high score is blocked on the CURRENT request,
// not only on the next one (which was the previous reactive behaviour).
func BehaviorAnalysis(cfg config.BehaviorConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)

			// Step 1: check score from prior history BEFORE serving the request.
			score := st.CalcBehaviorScore(r.Context(), ip, cfg.ScoreThreshold)
			if score >= cfg.ScoreThreshold {
				count, _ := st.IncrAutoBanCounter(r.Context(), ip)
				if count >= 3 {
					if err := st.BlockIP(r.Context(), ip); err == nil {
						log.Warn("behavior: auto-banned IP", map[string]any{
							"ip":    ip,
							"score": score,
						})
						st.IncrMetric(r.Context(), "behavior_autoban")
					}
				}
				SecurityDeny(w, r, log, st, "behavior_high_risk", ip, http.StatusTooManyRequests, map[string]any{
					"score":     score,
					"threshold": cfg.ScoreThreshold,
				})
				return
			}

			// Step 2: serve the request, capturing the response status.
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)

			// Step 3: record outcome so the NEXT request sees updated scores.
			st.RecordRequest(r.Context(), ip, r.URL.Path, sw.status)
		})
	}
}
