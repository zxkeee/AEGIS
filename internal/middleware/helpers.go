package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"api-gateway/internal/secevent"
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

// Unwrap exposes the underlying writer to http.ResponseController, so Flush
// (SSE) and Hijack (WebSocket) initiated by the reverse proxy reach the real
// connection through this wrapper.
func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

// trustedProxyNets holds pre-parsed CIDRs set via InitTrustedProxies. It is an
// atomic pointer (not a plain slice) because InitTrustedProxies also runs on
// config hot-reload, concurrently with RealIP reads on the request hot path.
// An atomic load per request is effectively free; the slice itself is immutable.
var trustedProxyNets atomic.Pointer[[]*net.IPNet]

// InitTrustedProxies parses CIDR strings (or bare IPs) from config and caches
// them. Called from main() before the servers start and again on every config
// hot-reload, so trusted_proxies changes take effect without a restart. Bare
// IPs are normalised to /32 (IPv4) or /128 (IPv6) host routes.
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
	trustedProxyNets.Store(&nets)
	return nil
}

// loadTrustedProxyNets returns the current immutable CIDR slice (nil when
// none configured).
func loadTrustedProxyNets() []*net.IPNet {
	if p := trustedProxyNets.Load(); p != nil {
		return *p
	}
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

	nets := loadTrustedProxyNets()
	if len(nets) == 0 {
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
		if isTrustedProxyIP(nets, ip) {
			continue
		}
		return chain[i]
	}

	// All hops were trusted (unusual but possible in all-internal topologies).
	return remoteHost
}

func isTrustedProxyIP(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
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
	nets := loadTrustedProxyNets()
	if len(nets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && isTrustedProxyIP(nets, ip)
}

// SecurityDeny logs, records metrics/forensics, and responds with an error.
func SecurityDeny(w http.ResponseWriter, r *http.Request,
	log Logger, st DenySink,
	reason, ip string, code int, extra map[string]any) {

	log.BlockEvent(reason, ip, r.URL.Path, r.Method, extra)
	st.IncrMetric(r.Context(), "blocked_"+reason)
	st.PushForensic(r.Context(), secevent.Entry{
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

// requestIDShape bounds a client-supplied X-Request-ID: short, and only
// characters that are safe to echo into logs, response headers and upstream
// requests. Anything else is replaced with a generated ID rather than
// propagated verbatim.
var requestIDShape = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// RequestID injects a unique X-Request-ID header for log correlation. A
// well-formed client-supplied ID is preserved (so traces can span systems);
// malformed or oversized values are discarded and regenerated.
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if !requestIDShape.MatchString(id) {
				b := make([]byte, 8)
				if _, err := rand.Read(b); err != nil {
					// crypto/rand should never fail; fall back to a time-based id so
					// correlation still works rather than emitting an all-zero id.
					id = fmt.Sprintf("%x", time.Now().UnixNano())
				} else {
					id = hex.EncodeToString(b)
				}
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
			// X-XSS-Protection is deliberately NOT set: the header is deprecated,
			// ignored by every current browser, and its legacy filter enabled
			// XS-Leaks in older ones. CSP (set by the dashboard) is the control.
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			next.ServeHTTP(w, r)
		})
	}
}
