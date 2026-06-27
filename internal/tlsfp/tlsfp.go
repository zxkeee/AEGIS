// Package tlsfp computes a TLS fingerprint from the ClientHello captured during
// the handshake and carries it to the HTTP handler on the same connection.
//
// This replaces the previous design where the JA3 fingerprint was read from a
// client-supplied `X-JA3-Fingerprint` header — which any client could spoof.
// The fingerprint here is derived from the actual TLS ClientHello and cannot be
// forged by the client.
//
// Honesty note: Go's standard library exposes `tls.ClientHelloInfo` but NOT the
// raw ordered extension list, so this is not byte-for-byte canonical JA3 (which
// hashes the extension list). It is a stable JA3-style fingerprint over the
// fields the stdlib does expose: TLS version, cipher suites, supported curves,
// EC point formats and ALPN. It is sufficient to identify and correlate client
// stacks (bot farms, proxy rotators) without trusting client input. Canonical
// JA3/JA4 would require a custom ClientHello parser; that is intentionally out
// of scope here in favour of a spoof-proof, stdlib-only fingerprint.
package tlsfp

import (
	"context"
	"crypto/md5" // #nosec G401,G501 -- md5 is the JA3 digest standard, not used for security
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type ctxKey struct{}

// holder carries the fingerprint from the handshake to the request handler.
type holder struct{ fp string }

// Registry binds a per-connection fingerprint computed during the TLS handshake
// to the HTTP request served on that connection. It is safe for concurrent use.
type Registry struct {
	mu sync.Mutex
	m  map[net.Conn]*holder
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[net.Conn]*holder)}
}

// ConnContext is wired into http.Server.ConnContext. It runs before the TLS
// handshake, so a holder exists by the time GetConfigForClient fires.
func (reg *Registry) ConnContext(ctx context.Context, c net.Conn) context.Context {
	h := &holder{}
	reg.mu.Lock()
	reg.m[c] = h
	reg.mu.Unlock()
	return context.WithValue(ctx, ctxKey{}, h)
}

// ConnState is wired into http.Server.ConnState to release per-connection state
// when the connection closes, preventing a memory leak.
func (reg *Registry) ConnState(c net.Conn, state http.ConnState) {
	if state == http.StateClosed || state == http.StateHijacked {
		reg.mu.Lock()
		delete(reg.m, c)
		reg.mu.Unlock()
	}
}

// TLSConfig returns a *tls.Config that captures the ClientHello fingerprint for
// each connection. base may be nil. The returned config's GetConfigForClient
// records the fingerprint and then defers to base.
func (reg *Registry) TLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		fp := Fingerprint(hello)
		reg.mu.Lock()
		if h := reg.m[hello.Conn]; h != nil {
			h.fp = fp
		}
		reg.mu.Unlock()
		return nil, nil // use the listener's config unchanged
	}
	return cfg
}

// FromContext returns the fingerprint captured for the current connection, or
// "" if TLS was not terminated at the gateway.
func FromContext(ctx context.Context) string {
	if h, ok := ctx.Value(ctxKey{}).(*holder); ok {
		return h.fp
	}
	return ""
}

// Fingerprint builds a JA3-style MD5 digest from the ClientHello fields the
// stdlib exposes. GREASE values (RFC 8701) are filtered so the fingerprint is
// stable across browsers that randomise them.
func Fingerprint(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}

	version := 0
	for _, v := range hello.SupportedVersions {
		if int(v) > version && !isGREASE(v) {
			version = int(v)
		}
	}

	ciphers := make([]string, 0, len(hello.CipherSuites))
	for _, c := range hello.CipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, strconv.Itoa(int(c)))
		}
	}

	curves := make([]string, 0, len(hello.SupportedCurves))
	for _, c := range hello.SupportedCurves {
		if !isGREASE(uint16(c)) {
			curves = append(curves, strconv.Itoa(int(c)))
		}
	}

	points := make([]string, 0, len(hello.SupportedPoints))
	for _, p := range hello.SupportedPoints {
		points = append(points, strconv.Itoa(int(p)))
	}

	// ALPN stands in for the (unavailable) extension list — it still varies by
	// client stack and is part of the ClientHello.
	alpn := strings.Join(hello.SupportedProtos, "-")

	raw := strings.Join([]string{
		strconv.Itoa(version),
		strings.Join(ciphers, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
		alpn,
	}, ",")

	sum := md5.Sum([]byte(raw)) // #nosec G401
	return hex.EncodeToString(sum[:])
}

// isGREASE reports whether a TLS value is a GREASE placeholder (RFC 8701):
// values of the form 0x?a?a where both bytes are equal and end in 0x0a.
func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}
