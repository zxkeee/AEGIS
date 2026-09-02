package middleware

import (
	"fmt"
	"net/http"

	"api-gateway/internal/alert"
	"api-gateway/internal/config"
)

// BehaviorAnalysis calculates a risk score for each request and blocks high-risk IPs.
//
// Flow (preventive, not reactive):
//  1. Score is calculated from the IP's PRIOR request history before the request is served.
//  2. If score >= threshold the request is blocked immediately.
//  3. After the request, metrics are recorded so the next request sees updated data.
//
// This means a SEQUENTIAL request from an IP that has built up a high score is
// blocked on that same request, not only on the next one (which was the
// previous, purely reactive behaviour). It is not a hard per-IP concurrency
// bound, though: step 3 only runs after the response completes, so a burst of
// CONCURRENT requests from the same IP can all read the same pre-burst score
// in step 1 and all pass before any of them has recorded outcomes for the
// others to see — a race window bounded by upstream latency × concurrency,
// not by this scoring logic. Volumetric bursts are RateLimit's job (a real
// atomic counter, see ratelimit.go); this middleware's guarantee is about
// score-driven blocking once elevated, not about capping in-flight bursts.
func BehaviorAnalysis(cfg config.BehaviorConfig, log Logger, st behaviorStore, al *Alerter) Middleware {
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
					if err := st.AutoBanIP(r.Context(), ip, cfg.AutoBanTTL); err == nil {
						log.Warn("behavior: auto-banned IP", map[string]any{
							"ip":    ip,
							"score": score,
							"ttl":   cfg.AutoBanTTL.String(),
						})
						st.IncrMetric(r.Context(), "behavior_autoban")
						// The gateway has just started refusing a client on its
						// own judgement. That is the other event the alerting
						// config names, and the one most likely to be a false
						// positive an operator wants to see quickly. Keyed by IP
						// so a ban storm from one source pages once.
						al.Notify(r.Context(), alert.SeverityWarning, "behavior_autoban:"+ip,
							"AEGIS: IP auto-banned on behaviour score",
							fmt.Sprintf("ip=%s score=%d threshold=%d ttl=%s", ip, score, cfg.ScoreThreshold, cfg.AutoBanTTL))
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
