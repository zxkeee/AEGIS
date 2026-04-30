package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"api-gateway/internal/store"
)

// statusWriter wraps ResponseWriter to capture the HTTP status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

// TrustedProxies defines a list of trusted proxy CIDRs.
// Only IPs from these ranges will have their X-Forwarded-For headers trusted.
var TrustedProxies = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"::1/128",
}

// RealIP extracts the client IP with trusted proxy validation.
// FIX SEC-1: Only trust X-Forwarded-For from known proxy IPs to prevent spoofing.
func RealIP(r *http.Request) string {
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Only trust forwarded headers if the direct connection is from a trusted proxy
	if isTrustedProxy(remoteHost) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if net.ParseIP(xri) != nil {
				return xri
			}
		}
	}

	return remoteHost
}

func isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range TrustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// SecurityDeny logs, records metrics/forensics, and responds with an error.
func SecurityDeny(w http.ResponseWriter, r *http.Request,
	log Logger, st Store,
	reason, ip string, code int, extra map[string]any) {

	log.BlockEvent(reason, ip, r.URL.Path, r.Method, extra)
	st.IncrMetric(r.Context(), "blocked_"+reason)
	st.PushForensic(r.Context(), store.ForensicEntry{
		Timestamp: time.Now().UTC(),
		IP:        ip,
		Path:      r.URL.Path,
		Method:    r.Method,
		Reason:    reason,
		Code:      code,
	})

	http.Error(w, "Access Denied", code)
}

// RequestID injects a unique X-Request-ID header for log correlation.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if id == "" {
				b := make([]byte, 8)
				rand.Read(b) //nolint:errcheck
				id = hex.EncodeToString(b)
			}
			r.Header.Set("X-Request-ID", id)
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds standard security headers to every response.
func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			next.ServeHTTP(w, r)
		})
	}
}
