package gatewayverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSecret = "a-strong-shared-secret-32-characters!!"

// signRequest reproduces exactly what AEGIS does in middleware/jwt.go so the
// reference verifier is tested against the real wire format. Identity is empty
// (no identity_claim configured); signRequestID covers the populated case.
func signRequest(secret, sub, roles, scopes, nonce string, ts int64) *http.Request {
	return signRequestID(secret, sub, roles, scopes, "", nonce, ts)
}

// signRequestID is signRequest plus the ownership-identity claim, mirroring the
// canonical payload sub:roles:scopes:identity:ts:nonce.
func signRequestID(secret, sub, roles, scopes, identity, nonce string, ts int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	tss := strconv.FormatInt(ts, 10)
	payload := strings.Join([]string{sub, roles, scopes, identity, tss, nonce}, ":")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))

	r.Header.Set(HeaderSubject, sub)
	if roles != "" {
		r.Header.Set(HeaderRoles, roles)
	}
	if scopes != "" {
		r.Header.Set(HeaderScopes, scopes)
	}
	if identity != "" {
		r.Header.Set(HeaderIdentity, identity)
	}
	r.Header.Set(HeaderTimestamp, tss)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderSignature, hex.EncodeToString(mac.Sum(nil)))
	return r
}

// TestVerify_IdentityIsAuthenticated confirms the ownership-identity claim is
// covered by the signature: a valid identity is returned, and forging it
// (without re-signing) is rejected — the gap that let a directly-reachable
// backend trust an unsigned X-Gateway-Identity.
func TestVerify_IdentityIsAuthenticated(t *testing.T) {
	v := New(testSecret, time.Minute, NewMemoryNonceStore())

	r := signRequestID(testSecret, "user-7", "", "", "42", "id-nonce-1", time.Now().Unix())
	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if id.Identity != "42" {
		t.Errorf("identity = %q, want 42", id.Identity)
	}

	// Forge the identity header without re-signing: must be rejected.
	tampered := signRequestID(testSecret, "user-7", "", "", "42", "id-nonce-2", time.Now().Unix())
	tampered.Header.Set(HeaderIdentity, "99")
	if _, err := v.Verify(tampered); err != ErrBadSignature {
		t.Fatalf("tampered identity: got %v, want ErrBadSignature", err)
	}
}

func TestVerify_HappyPath(t *testing.T) {
	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	r := signRequest(testSecret, "user-7", "admin,viewer", "read write", "nonce-1", time.Now().Unix())

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if id.Subject != "user-7" {
		t.Errorf("subject = %q", id.Subject)
	}
	if !id.HasRole("admin") || !id.HasRole("viewer") || id.HasRole("root") {
		t.Errorf("roles = %v", id.Roles)
	}
	if len(id.Scopes) != 2 || id.Scopes[0] != "read" {
		t.Errorf("scopes = %v", id.Scopes)
	}
}

func TestVerify_TamperedSubject(t *testing.T) {
	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	r := signRequest(testSecret, "user-7", "viewer", "", "nonce-2", time.Now().Unix())
	r.Header.Set(HeaderSubject, "admin") // attacker swaps identity after signing

	if _, err := v.Verify(r); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	v := New("a-different-secret-value-of-length-32!", time.Minute, NewMemoryNonceStore())
	r := signRequest(testSecret, "user-7", "", "", "nonce-3", time.Now().Unix())

	if _, err := v.Verify(r); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerify_Stale(t *testing.T) {
	v := New(testSecret, 30*time.Second, NewMemoryNonceStore())
	r := signRequest(testSecret, "user-7", "", "", "nonce-4", time.Now().Add(-2*time.Minute).Unix())

	if _, err := v.Verify(r); err != ErrStale {
		t.Fatalf("expected ErrStale, got %v", err)
	}
}

func TestVerify_FutureTimestampStale(t *testing.T) {
	v := New(testSecret, 30*time.Second, NewMemoryNonceStore())
	r := signRequest(testSecret, "user-7", "", "", "nonce-5", time.Now().Add(2*time.Minute).Unix())

	if _, err := v.Verify(r); err != ErrStale {
		t.Fatalf("expected ErrStale for future ts, got %v", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	now := time.Now().Unix()
	first := signRequest(testSecret, "user-7", "", "", "dupe-nonce", now)
	if _, err := v.Verify(first); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	second := signRequest(testSecret, "user-7", "", "", "dupe-nonce", now)
	if _, err := v.Verify(second); err != ErrReplay {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
}

func TestVerify_MissingHeaders(t *testing.T) {
	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := v.Verify(r); err != ErrMissingHeaders {
		t.Fatalf("expected ErrMissingHeaders, got %v", err)
	}
}

func TestVerify_BadTimestamp(t *testing.T) {
	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	r := signRequest(testSecret, "user-7", "", "", "nonce-6", time.Now().Unix())
	r.Header.Set(HeaderTimestamp, "not-a-number")
	if _, err := v.Verify(r); err != ErrBadTimestamp {
		t.Fatalf("expected ErrBadTimestamp, got %v", err)
	}
}

func TestHandler_RejectsAndAllows(t *testing.T) {
	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	var sawIdentity Identity
	h := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawIdentity, _ = FromContext(r)
		w.WriteHeader(http.StatusOK)
	}))

	// Reject: no headers.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// Allow: valid signature.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signRequest(testSecret, "user-9", "admin", "", "h-nonce", time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if sawIdentity.Subject != "user-9" {
		t.Fatalf("handler did not receive identity, got %q", sawIdentity.Subject)
	}
}
