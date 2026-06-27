package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"api-gateway/internal/store"
	"api-gateway/internal/tenant"
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

// trustedProxyNets holds pre-parsed CIDRs set once at startup via InitTrustedProxies.
// Reads happen on every request (hot path) so we avoid locks by making it immutable
// after init — a new slice is swapped in atomically via package-level replace at startup.
var trustedProxyNets []*net.IPNet

// InitTrustedProxies parses CIDR strings (or bare IPs) from config and caches them.
// Must be called once from main() before starting servers. Bare IPs are normalised
// to /32 (IPv4) or /128 (IPv6) host routes.
func InitTrustedProxies(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		// Accept bare IPs as well as CIDRs.
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			s = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("trusted_proxies: invalid CIDR %q: %w", s, err)
		}
		nets = append(nets, ipNet)
	}
	trustedProxyNets = nets
	return nil
}

// RealIP returns the originating client IP using a right-to-left walk of the
// X-Forwarded-For chain.  Only IPs that are explicitly listed in trusted_proxies
// are skipped; the first non-trusted IP encountered is returned as the real client.
//
// Why right-to-left?  Each hop appends its view of the sender to XFF.  Our
// trusted load balancer appends the real client IP; everything to its left is
// attacker-controlled.  Walking right-to-left and stopping at the first
// untrusted entry is immune to prefix-spoofing.
//
// If no trusted proxies are configured, RemoteAddr is always used directly.
func RealIP(r *http.Request) string {
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)

	if len(trustedProxyNets) == 0 {
		return remoteHost
	}

	// Build the full candidate chain: XFF entries + RemoteAddr at the end.
	var chain []string
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			if ip := strings.TrimSpace(part); ip != "" {
				chain = append(chain, ip)
			}
		}
	}
	chain = append(chain, remoteHost)

	// Walk right-to-left.  Skip trusted hops; return the first untrusted one.
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(chain[i])
		if ip == nil {
			continue
		}
		if isTrustedProxyIP(ip) {
			continue
		}
		return chain[i]
	}

	// All hops were trusted (unusual but possible in all-internal topologies).
	return remoteHost
}

func isTrustedProxyIP(ip net.IP) bool {
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// RemotePeerTrusted reports whether the immediate TCP peer (r.RemoteAddr) is a
// configured trusted proxy. Used to decide whether to believe headers injected
// by that upstream (e.g. a Cloudflare-supplied JA3 hash). With no trusted
// proxies configured, nothing is trusted.
func RemotePeerTrusted(r *http.Request) bool {
	if len(trustedProxyNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && isTrustedProxyIP(ip)
}

// SecurityDeny logs, records metrics/forensics, and responds with an error.
func SecurityDeny(w http.ResponseWriter, r *http.Request,
	log Logger, st Store,
	reason, ip string, code int, extra map[string]any) {

	log.BlockEvent(reason, ip, r.URL.Path, r.Method, extra)
	st.IncrMetric(r.Context(), "blocked_"+reason)
	st.PushForensic(r.Context(), store.ForensicEntry{
		Tenant:    tenant.From(r.Context()),
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
