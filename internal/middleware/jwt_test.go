package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/config"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "0123456789abcdef0123456789abcdef" // 32 chars

func hsToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rsToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func serveJWT(cfg config.AuthConfig, st Store, authz string) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	ja := NewJWTAuth(cfg, fakeLogger{}, st)
	var passedSubject string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passedSubject = r.Header.Get("X-Gateway-Subject")
		w.Header().Set("X-Test-Subject", passedSubject)
		w.WriteHeader(http.StatusOK)
	})
	h := ja.Middleware()(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1"
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	h.ServeHTTP(rec, r)
	return rec
}

func TestJWT_ValidHMAC_Passes(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret}
	st := &fakeStore{}
	tok := hsToken(t, testSecret, jwt.MapClaims{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()})
	rec := serveJWT(cfg, st, "Bearer "+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid HMAC token: got %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-Test-Subject") != "alice" {
		t.Fatal("subject was not propagated downstream")
	}
}

// A correctly-signed token with no "exp" claim must be rejected — otherwise it
// never expires. golang-jwt does not enforce this without WithExpirationRequired.
func TestJWT_NoExpiry_Rejected(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret}
	tok := hsToken(t, testSecret, jwt.MapClaims{"sub": "alice"}) // no exp
	rec := serveJWT(cfg, &fakeStore{}, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token without exp: got %d, want 401", rec.Code)
	}
}

func TestJWT_AlgConfusion_HMACModeRejectsRSA(t *testing.T) {
	// Only a shared secret is configured. An RSA-signed token must be rejected,
	// not treated as if it were HMAC-signed.
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret}
	tok := rsToken(t, jwt.MapClaims{"sub": "attacker", "exp": time.Now().Add(time.Hour).Unix()})
	rec := serveJWT(cfg, &fakeStore{}, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("RSA token in HMAC mode: got %d, want 401", rec.Code)
	}
}

func TestJWT_EmptySecret_RejectsAll(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: ""}
	tok := hsToken(t, "", jwt.MapClaims{"sub": "x", "exp": time.Now().Add(time.Hour).Unix()})
	rec := serveJWT(cfg, &fakeStore{}, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty-secret HMAC: got %d, want 401", rec.Code)
	}
}

func TestJWT_JWKSConfiguredButUnavailable_FailsClosed(t *testing.T) {
	// JWKS is configured but the keys cannot load. The gateway must NOT fall back
	// to HMAC; every token is rejected until keys are available.
	cfg := config.AuthConfig{Enabled: true, JWKSURL: "https://127.0.0.1:1/jwks.json", Secret: testSecret}
	tok := hsToken(t, testSecret, jwt.MapClaims{"sub": "x", "exp": time.Now().Add(time.Hour).Unix()})
	rec := serveJWT(cfg, &fakeStore{}, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("JWKS-unavailable fallback: got %d, want 401 (must fail closed)", rec.Code)
	}
}

func TestJWT_RevokedJTI_Rejected(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret}
	st := &fakeStore{jtiRevoked: map[string]bool{"revoked-1": true}}
	tok := hsToken(t, testSecret, jwt.MapClaims{"sub": "alice", "jti": "revoked-1", "exp": time.Now().Add(time.Hour).Unix()})
	rec := serveJWT(cfg, st, "Bearer "+tok)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: got %d, want 401", rec.Code)
	}
}

func TestJWT_MissingHeader_Rejected(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret}
	rec := serveJWT(cfg, &fakeStore{}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing Authorization: got %d, want 401", rec.Code)
	}
}

// TestJWT_RevocationFailOpen_DefaultProceeds verifies the default behaviour: when
// the JTI-revocation lookup errors (Redis outage) and revocation_fail_closed is
// unset, the request proceeds (availability over strictness) — preserving the
// pre-existing contract.
func TestJWT_RevocationFailOpen_DefaultProceeds(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret}
	st := &fakeStore{jtiErr: errors.New("redis down")}
	tok := hsToken(t, testSecret, jwt.MapClaims{
		"sub": "alice", "jti": "abc", "exp": time.Now().Add(time.Hour).Unix(),
	})
	rec := serveJWT(cfg, st, "Bearer "+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("fail-open default: got %d, want 200", rec.Code)
	}
}

// TestJWT_RevocationFailClosed_Denies verifies high-assurance mode: when the
// revocation lookup errors and revocation_fail_closed is set, the request is
// denied so a revoked token can never slip through during an outage.
func TestJWT_RevocationFailClosed_Denies(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret, RevocationFailClosed: true}
	st := &fakeStore{jtiErr: errors.New("redis down")}
	tok := hsToken(t, testSecret, jwt.MapClaims{
		"sub": "alice", "jti": "abc", "exp": time.Now().Add(time.Hour).Unix(),
	})
	rec := serveJWT(cfg, st, "Bearer "+tok)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed: got %d, want 503", rec.Code)
	}
}
