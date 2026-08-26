package middleware

import (
	"fmt"
	"net/http"
	"time"
)

// licenseRateKey is a single fixed key, not per-IP/per-route: MaxRPS is a
// commercial ceiling on the WHOLE gateway's throughput (what the license was
// sold for), not a per-client control — that's what RateLimit/RouteRateLimit
// already do, and are unaffected by this running alongside them.
const licenseRateKey = "license:global:rps"

// LicenseRateLimit enforces the advisory MaxRPS ceiling from the active
// license (Claims.MaxRPS, set via cmd/gateway/main.go into
// config.GatewayConfig.LicenseMaxRPS). maxRPS <= 0 means "no cap" (most
// licenses today are issued without one) and returns passthrough — a
// license without MaxRPS set costs nothing here.
//
// This is a commercial constraint, not a security control: unlike
// RateLimit/RouteRateLimit, it deliberately has no fail_closed option and
// always fails OPEN on a store error. A Redis hiccup must never turn a
// licensing technicality into a customer-facing outage — the same
// reasoning CLAUDE.md gives for behavioral scoring staying fail-open.
func LicenseRateLimit(maxRPS int, log Logger, st rateLimitStore) Middleware {
	if maxRPS <= 0 {
		return passthrough
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count, err := st.IncrRate(r.Context(), licenseRateKey, time.Second)
			if err != nil {
				log.Error("license_rate_limit: store error, failing open", map[string]any{"error": err.Error()})
				next.ServeHTTP(w, r)
				return
			}
			if count > int64(maxRPS) {
				ip := RealIP(r)
				SecurityDeny(w, r, log, st, "license_rps_cap_exceeded", ip, http.StatusTooManyRequests,
					map[string]any{"count": count, "licensed_max_rps": maxRPS})
				return
			}
			w.Header().Set("X-License-RPS-Limit", fmt.Sprintf("%d", maxRPS))
			next.ServeHTTP(w, r)
		})
	}
}
