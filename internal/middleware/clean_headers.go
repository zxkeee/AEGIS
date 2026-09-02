package middleware

import (
	"net/http"
	"strings"
)

// spoofableForwardHeaders are the client-supplied forwarding/identity headers a
// backend commonly trusts (IP allowlists, rate limits, absolute-URL generation,
// logging). When the immediate TCP peer is not a configured trusted proxy these
// are attacker-controlled, so the gateway strips them before forwarding and then
// sets an authoritative X-Real-IP / X-Forwarded-For itself.
var spoofableForwardHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-IP",
	"Forwarded",
	"True-Client-IP",
	"CF-Connecting-IP",
}

// CleanHeaders is a security middleware that drops incoming headers a client must
// never be able to forge:
//
//   - X-Gateway-*  — the signed identity the gateway itself injects post-auth.
//   - X-JA3-Fingerprint — set only by the TLSFingerprint middleware from the real
//     ClientHello.
//   - X-Forwarded-* / X-Real-IP / Forwarded — the forwarding chain. From an
//     untrusted peer these are spoofed; a backend trusting them is open to IP
//     spoofing and X-Forwarded-Host cache/link poisoning. They are kept only when
//     the immediate peer is a configured trusted_proxy (a real upstream LB), in
//     which case they are authoritative.
func CleanHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for headerName := range r.Header {
				if strings.HasPrefix(strings.ToLower(headerName), "x-gateway-") {
					r.Header.Del(headerName)
				}
			}
			// SEC (P0-4): the TLS fingerprint is gateway-internal. A client must
			// never be able to supply it — only the TLSFingerprint middleware may
			// set it, from the real ClientHello. Strip any inbound value.
			r.Header.Del("X-JA3-Fingerprint")

			// Forwarding headers: trust them only from a configured trusted proxy.
			// From anyone else (a direct client) they are spoofable, so strip the
			// whole family. This runs before RealIP-dependent controls and before
			// the proxy forwards.
			//
			// X-Forwarded-For is left deleted on purpose: the reverse proxy
			// (httputil) re-sets it to the real client IP when forwarding, so the
			// backend gets a single authoritative entry with no attacker prefix.
			if !RemotePeerTrusted(r) {
				for _, h := range spoofableForwardHeaders {
					r.Header.Del(h)
				}
			}

			// X-Real-IP is re-asserted for EVERY request, trusted peer or not.
			//
			// It used to be set only on the untrusted branch, so a client behind a
			// real load balancer could send its own X-Real-IP and have it forwarded
			// untouched: the gateway resolved the caller from the X-Forwarded-For
			// chain and logged, rate-limited and banned one address while the
			// backend's own IP allowlist read a different one the caller had chosen
			// — 127.0.0.1, say. Two components disagreeing about who the client is,
			// which is the whole class of confusion this file exists to remove.
			//
			// RealIP is the gateway's own verdict, derived from the trusted-proxy
			// walk. Forwarding exactly that keeps the backend's view identical to
			// the one every control here acted on. Where an upstream sets X-Real-IP
			// but no X-Forwarded-For, this replaces its value with the peer address
			// the gateway itself used — the honest answer, and the one that keeps
			// the two ends consistent.
			if realIP := RealIP(r); realIP != "" {
				r.Header.Set("X-Real-IP", realIP)
			}

			next.ServeHTTP(w, r)
		})
	}
}
