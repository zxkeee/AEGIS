package middleware

import (
	"net/http"

	"api-gateway/internal/config"
	"api-gateway/internal/tlsfp"
)

// TLSFingerprint injects the real TLS fingerprint — computed from the
// ClientHello during the handshake (see internal/tlsfp) — into the internal
// X-JA3-Fingerprint header so downstream middleware (bot detection, behavioural
// scoring) can consume it.
//
// It must run AFTER CleanHeaders, which strips any client-supplied
// X-JA3-Fingerprint. When TLS is terminated upstream (not at the gateway) the
// fingerprint is empty and the header is left unset, so no spoofable value ever
// reaches the detection logic.
func TLSFingerprint() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if fp := tlsfp.FromContext(r.Context()); fp != "" {
				r.Header.Set("X-JA3-Fingerprint", fp)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UpstreamFingerprint trusts a JA3 hash supplied by a trusted upstream that
// terminates TLS (e.g. Cloudflare). It is only meaningful in topologies where
// the gateway itself does NOT terminate TLS, so TLSFingerprint produces nothing.
//
// Security: the upstream header is believed only when the immediate peer is a
// trusted proxy (trusted_proxies). A direct client cannot spoof it — and the
// gateway's internal X-JA3-Fingerprint was already stripped by CleanHeaders, so
// this is the only path by which an externally-sourced JA3 can be set. It must
// run AFTER CleanHeaders and may run before or after TLSFingerprint (a real
// gateway-terminated fingerprint, when present, takes precedence).
func UpstreamFingerprint(cfg config.BotConfig) Middleware {
	if !cfg.TrustUpstreamJA3 {
		return passthrough
	}
	header := cfg.UpstreamJA3Header
	if header == "" {
		header = "Cf-Ja3-Hash"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.Header.Get(header); v != "" {
				if RemotePeerTrusted(r) {
					// Only set if a gateway-terminated fingerprint isn't already present.
					if r.Header.Get("X-JA3-Fingerprint") == "" {
						r.Header.Set("X-JA3-Fingerprint", v)
					}
				}
				// Never forward the upstream header to the backend.
				r.Header.Del(header)
			}
			next.ServeHTTP(w, r)
		})
	}
}
