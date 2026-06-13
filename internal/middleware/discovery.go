package middleware

import (
	"context"
	"net/http"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
)

// Catalog is the dependency the Discovery middleware records observations to.
// Implemented by *discovery.Catalog.
type Catalog interface {
	Record(obs discovery.Observation)
}

// obsKey is the private context key under which the per-request Observation
// accumulator pointer is stored. Inner middleware (JWT, DLP) enrich it; the
// Discovery middleware finalises and records it.
type obsKeyType struct{}

var obsKey = obsKeyType{}

// observationFrom returns the in-flight Observation accumulator, or nil.
func observationFrom(ctx context.Context) *discovery.Observation {
	o, _ := ctx.Value(obsKey).(*discovery.Observation)
	return o
}

// Discovery passively catalogs every API call that reaches the proxy. It seeds
// an Observation into the request context (so inner middleware can attach
// identity and PII signals), measures latency and status, and records the
// result to the catalog. It must sit inside the auth/DLP middleware so those can
// enrich the observation, and outside the proxy so it captures the final status.
func Discovery(cfg config.APIInventoryConfig, cat Catalog, log Logger) Middleware {
	if !cfg.Enabled || cat == nil {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			obs := &discovery.Observation{
				Method:     r.Method,
				Path:       r.URL.Path,
				ConsumerIP: RealIP(r),
			}
			ctx := context.WithValue(r.Context(), obsKey, obs)

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(sw, r.WithContext(ctx))

			// Endpoints that don't exist (404) are not part of the company's API
			// surface — skip them so probing can't pollute the catalog.
			if sw.status == http.StatusNotFound {
				return
			}

			obs.Status = sw.status
			obs.LatencyMs = time.Since(start).Milliseconds()
			cat.Record(*obs)

			log.Info("api_access", map[string]any{
				"method":     obs.Method,
				"path":       obs.Path,
				"status":     obs.Status,
				"latency_ms": obs.LatencyMs,
				"consumer":   consumerLabel(obs),
				"ip":         obs.ConsumerIP,
				"request_id": r.Header.Get("X-Request-ID"),
			})
		})
	}
}

// consumerLabel picks the strongest available consumer identity for logging.
func consumerLabel(obs *discovery.Observation) string {
	switch {
	case obs.ConsumerSubject != "":
		return "jwt:" + obs.ConsumerSubject
	case obs.ConsumerKey != "":
		return "key:" + obs.ConsumerKey
	default:
		return "ip:" + obs.ConsumerIP
	}
}
