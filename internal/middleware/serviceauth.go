package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"api-gateway/internal/config"
)

// ServiceAuth validates HMAC signatures for service-to-service communication.
func ServiceAuth(cfg config.RegistryConfig, log Logger, st Store, reg RegistryProvider) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serviceID := r.Header.Get("X-Service-ID")
			signature := r.Header.Get("X-Service-Signature")

			if serviceID == "" || signature == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Lookup service secret
			secret, ok, err := reg.LookupService(r.Context(), serviceID)
			if err != nil {
				log.Error("service_auth: registry error", map[string]any{"error": err.Error()})
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if !ok {
				SecurityDeny(w, r, log, st, "service_unknown", RealIP(r), http.StatusForbidden,
					map[string]any{"service_id": serviceID})
				return
			}

			// Verify HMAC
			payload := strings.Join([]string{
				r.Method,
				r.URL.Path,
				r.Header.Get("X-Timestamp"),
			}, "\n")

			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(payload))
			expected := hex.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(signature), []byte(expected)) {
				SecurityDeny(w, r, log, st, "service_bad_signature", RealIP(r), http.StatusForbidden,
					map[string]any{"service_id": serviceID})
				return
			}

			// Check service-specific rate limits
			allowed, err := reg.CheckRateLimit(r.Context(), serviceID, config.RateLimitConfig{})
			if err != nil {
				log.Error("service_auth: rate limit error", map[string]any{"error": err.Error()})
			}
			if !allowed {
				SecurityDeny(w, r, log, st, "service_rate_exceeded", RealIP(r), http.StatusTooManyRequests,
					map[string]any{"service_id": serviceID})
				return
			}

			r.Header.Set("X-Gateway-Service", serviceID)
			next.ServeHTTP(w, r)
		})
	}
}
