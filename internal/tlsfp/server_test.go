package tlsfp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestRegistry_FingerprintReachesHandlerOverRealTLS drives a real http.Server
// over a real TLS handshake, wired exactly as cmd/gateway/main.go wires it.
//
// It exists because the unit test one file over could not have caught the bug it
// replaces. That test builds its own ClientHelloInfo and sets Conn to the same
// object it passed to ConnContext — which assumes the very thing that was
// false. In a real server the two differ: ServeTLS wraps the listener with
// tls.NewListener, so ConnContext receives a *tls.Conn, while crypto/tls sets
// ClientHelloInfo.Conn to the underlying *net.TCPConn. The lookup missed every
// time, the fingerprint was stored nowhere, and every request read "".
//
// The whole package was therefore inert in production: X-JA3-Fingerprint was
// never set, bot.blocked_ja3 could never match, and CheckJA3Consistency never
// saw a value — while the package doc promised a fingerprint that "cannot be
// forged by the client". Only an end-to-end handshake can hold that promise
// honest, so this test performs one.
func TestRegistry_FingerprintReachesHandlerOverRealTLS(t *testing.T) {
	certPEM, keyPEM := selfSignedCert(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	reg := NewRegistry()
	got := make(chan string, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got <- FromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
		ConnContext:       reg.ConnContext,
		ConnState:         reg.ConnState,
		ReadHeaderTimeout: 5 * time.Second,
	}
	srv.TLSConfig = reg.TLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.ServeTLS(ln, "", "") }()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
	}}

	// The listener is up before ServeTLS runs, so a connection refused here would
	// be a real failure, not a startup race; retry only briefly for scheduling.
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = client.Get("https://" + ln.Addr().String() + "/")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case fp := <-got:
		if fp == "" {
			t.Fatal("no fingerprint reached the handler: the registry never bound the ClientHello to this connection, so every JA3-dependent control is inert")
		}
		if len(fp) != 32 {
			t.Errorf("fingerprint = %q, want a 32-char MD5 digest", fp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler was never invoked")
	}
}

// The registry must also release its per-connection state after a real
// handshake, or a long-lived gateway leaks a holder per connection.
func TestRegistry_ReleasesStateAfterRealConnection(t *testing.T) {
	certPEM, keyPEM := selfSignedCert(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	reg := NewRegistry()
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		ConnContext:       reg.ConnContext,
		ConnState:         reg.ConnState,
		ReadHeaderTimeout: 5 * time.Second,
	}
	srv.TLSConfig = reg.TLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.ServeTLS(ln, "", "") }()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: tr}
	for i := 0; i < 5; i++ {
		resp, err := client.Get("https://" + ln.Addr().String() + "/")
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = resp.Body.Close()
	}
	tr.CloseIdleConnections()

	// ConnState(StateClosed) is delivered asynchronously as connections tear down.
	deadline := time.Now().Add(3 * time.Second)
	for {
		reg.mu.Lock()
		n := len(reg.m)
		reg.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connection holders still registered after every connection closed", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// selfSignedCert issues a throwaway certificate for the loopback listener.
func selfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}
