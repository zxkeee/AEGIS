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
	"api-gateway/sdk/gatewayverify"

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

// A configured identity_claim is propagated as X-Gateway-Identity (numeric
// claims stringified cleanly) so ownership detection can compare against a
// caller id that is not the subject.
func TestJWT_PropagatesIdentityClaim(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret, IdentityClaim: "uid"}
	var gotIdentity, gotSubject string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = r.Header.Get("X-Gateway-Identity")
		gotSubject = r.Header.Get("X-Gateway-Subject")
		w.WriteHeader(http.StatusOK)
	})
	_ = InitTrustedProxies(nil)
	h := NewJWTAuth(cfg, fakeLogger{}, &fakeStore{}).Middleware()(next)
	tok := hsToken(t, testSecret, jwt.MapClaims{
		"sub": "alice@example.com", "uid": 42, "exp": time.Now().Add(time.Hour).Unix(),
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1"
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: got %d", rec.Code)
	}
	if gotSubject != "alice@example.com" {
		t.Fatalf("subject = %q, want alice@example.com", gotSubject)
	}
	if gotIdentity != "42" {
		t.Fatalf("X-Gateway-Identity = %q, want 42 (numeric uid claim)", gotIdentity)
	}
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

// TestJWT_ObserveSoftAuth verifies pilot/observe mode: identity is still
// extracted and propagated from a VALID token, but a missing or invalid token
// passes THROUGH (no 401) instead of blocking traffic the backend would accept.
func TestJWT_ObserveSoftAuth(t *testing.T) {
	cfg := config.AuthConfig{Enabled: true, Secret: testSecret, Observe: true}
	st := &fakeStore{}

	// (a) valid token: passes, identity propagated.
	good := hsToken(t, testSecret, jwt.MapClaims{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()})
	rec := serveJWT(cfg, st, "Bearer "+good)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Test-Subject") != "alice" {
		t.Fatalf("observe valid token: code=%d subject=%q, want 200/alice", rec.Code, rec.Header().Get("X-Test-Subject"))
	}

	// (b) missing token: soft pass-through, NOT 401, no identity.
	rec = serveJWT(cfg, st, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("observe missing token: got %d, want 200 (soft pass-through)", rec.Code)
	}
	if rec.Header().Get("X-Test-Subject") != "" {
		t.Fatal("observe missing token: no identity should be propagated")
	}

	// (c) invalid signature: soft pass-through, NOT 401.
	bad := hsToken(t, "a-totally-different-secret-32chars!!", jwt.MapClaims{"sub": "mallory", "exp": time.Now().Add(time.Hour).Unix()})
	rec = serveJWT(cfg, st, "Bearer "+bad)
	if rec.Code != http.StatusOK {
		t.Fatalf("observe invalid token: got %d, want 200 (soft pass-through)", rec.Code)
	}
	if rec.Header().Get("X-Test-Subject") != "" {
		t.Fatal("observe invalid token: no identity should be propagated")
	}

	// Contrast: enforce mode still rejects missing / invalid tokens with 401.
	enforce := config.AuthConfig{Enabled: true, Secret: testSecret}
	if got := serveJWT(enforce, st, "").Code; got != http.StatusUnauthorized {
		t.Fatalf("enforce missing token: got %d, want 401", got)
	}
	if got := serveJWT(enforce, st, "Bearer "+bad).Code; got != http.StatusUnauthorized {
		t.Fatalf("enforce invalid token: got %d, want 401", got)
	}
}

// auth.exclude is one operator setting with two implementations: this one and
// discovery.authExcluded, which the chain consults to pick enforcing vs
// identify-only. They used to disagree on case, so the looser (case-insensitive)
// rule decided every request and this check never got a say — a policy whose
// weaker spelling silently won. They must agree.
func TestJWT_ExcludeIsCaseInsensitive(t *testing.T) {
	ja := NewJWTAuth(config.AuthConfig{Enabled: true, Secret: "s", Exclude: []string{"/Public"}},
		fakeLogger{}, &fakeStore{})
	h := ja.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, p := range []string{"/Public", "/public", "/PUBLIC", "/public/info", "/PuBlIc/info"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: got %d, want 200 — the exclusion must not depend on case", p, rec.Code)
		}
	}
	// An adjacent path is still not excluded: the boundary rule is unchanged.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/publicity", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("/publicity: got %d, want 401 — case-insensitivity must not widen the prefix", rec.Code)
	}
}

// What the gateway signs, the reference SDK must accept — and nothing else.
//
// Until this test existed, nothing checked the two against each other. The
// gateway built the signed payload here and sdk/gatewayverify built it again
// independently, so the wire format was defined twice and a change to either
// side would have kept passing on its own tests while breaking every backend.
// That is also how the format stayed delimiter-joined and non-injective on both
// sides for as long as it did.
func TestJWT_SignedIdentityVerifiesWithTheReferenceSDK(t *testing.T) {
	const propSecret = "propagation-secret-32-characters!!!!"
	cfg := config.AuthConfig{
		Enabled: true, Secret: testSecret,
		PropagationSecret: propSecret, IdentityClaim: "uid",
	}
	var forwarded *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r
		w.WriteHeader(http.StatusOK)
	})
	_ = InitTrustedProxies(nil)
	h := NewJWTAuth(cfg, fakeLogger{}, &fakeStore{}).Middleware()(next)

	// A subject containing the old delimiter: ordinary (URNs, issuer-qualified
	// OIDC subjects) and precisely the shape that used to be re-splittable.
	tok := hsToken(t, testSecret, jwt.MapClaims{
		"sub":   "urn:user:alice",
		"uid":   42,
		"roles": []any{"admin", "billing"},
		"scope": "read:orders write:orders",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1"
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if forwarded == nil {
		t.Fatal("the request never reached the upstream")
	}
	v := gatewayverify.New(propSecret, time.Minute, gatewayverify.NewMemoryNonceStore())
	id, err := v.Verify(forwarded)
	if err != nil {
		t.Fatalf("the SDK rejected what the gateway signed: %v", err)
	}
	if id.Subject != "urn:user:alice" {
		t.Fatalf("subject = %q, want urn:user:alice", id.Subject)
	}
	if id.Identity != "42" {
		t.Fatalf("identity = %q, want 42", id.Identity)
	}

	// And the same signature must not authenticate a re-split of those bytes.
	tampered := forwarded.Clone(forwarded.Context())
	tampered.Header.Set("X-Gateway-Subject", "urn:user")
	tampered.Header.Set("X-Gateway-Roles", "alice:admin,billing")
	v2 := gatewayverify.New(propSecret, time.Minute, gatewayverify.NewMemoryNonceStore())
	if _, err := v2.Verify(tampered); err == nil {
		t.Fatal("a re-split of the signed bytes authenticated a different subject")
	}
}
