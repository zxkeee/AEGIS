package tlsfp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestFingerprint_DeterministicAndDistinct(t *testing.T) {
	a := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
	b := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
	}

	fa1, fa2 := Fingerprint(a), Fingerprint(a)
	if fa1 != fa2 {
		t.Fatal("fingerprint not deterministic")
	}
	if len(fa1) != 32 {
		t.Fatalf("expected 32-char md5 hex, got %q", fa1)
	}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("distinct ClientHellos produced identical fingerprints")
	}
}

func TestFingerprint_GREASEStable(t *testing.T) {
	base := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519},
	}
	// Same hello but with GREASE values sprinkled in (RFC 8701).
	withGrease := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{0x0a0a, tls.VersionTLS13},
		CipherSuites:      []uint16{0x1a1a, tls.TLS_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{0x2a2a, tls.X25519},
	}
	if Fingerprint(base) != Fingerprint(withGrease) {
		t.Fatal("GREASE values changed the fingerprint; should be filtered")
	}
}

func TestFingerprint_Nil(t *testing.T) {
	if Fingerprint(nil) != "" {
		t.Fatal("nil hello should yield empty fingerprint")
	}
}

func TestIsGREASE(t *testing.T) {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xdada, 0xfafa}
	for _, g := range grease {
		if !isGREASE(g) {
			t.Errorf("%#x should be GREASE", g)
		}
	}
	for _, n := range []uint16{tls.VersionTLS13, 0x1301, 0x0a0b, 0x1a2a} {
		if isGREASE(n) {
			t.Errorf("%#x should not be GREASE", n)
		}
	}
}

func TestRegistry_Lifecycle(t *testing.T) {
	reg := NewRegistry()
	c1, c2 := &fakeConn{id: 1}, &fakeConn{id: 2}

	ctx := reg.ConnContext(context.Background(), c1)
	reg.ConnContext(context.Background(), c2)

	// Simulate the handshake capturing a fingerprint for c1.
	hello := &tls.ClientHelloInfo{
		Conn:              c1,
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
	}
	reg.TLSConfig(nil).GetConfigForClient(hello) //nolint:errcheck

	if got := FromContext(ctx); got == "" {
		t.Fatal("fingerprint not propagated to connection context")
	}
	if got, want := FromContext(ctx), Fingerprint(hello); got != want {
		t.Fatalf("context fp = %q, want %q", got, want)
	}

	// Closing the connection releases its holder.
	reg.ConnState(c1, http.StateClosed)
	reg.mu.Lock()
	_, present := reg.m[c1]
	reg.mu.Unlock()
	if present {
		t.Fatal("holder for closed conn was not released")
	}
}

func TestFromContext_Empty(t *testing.T) {
	if FromContext(context.Background()) != "" {
		t.Fatal("empty context should yield empty fingerprint")
	}
}

// fakeConn is a minimal net.Conn for registry keying.
type fakeConn struct{ id int }

func (f *fakeConn) Read(b []byte) (int, error)       { return 0, nil }
func (f *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return nil }
func (f *fakeConn) RemoteAddr() net.Addr             { return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
