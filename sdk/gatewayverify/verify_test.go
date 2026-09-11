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
// canonical payload built by CanonicalPayload.
func signRequestID(secret, sub, roles, scopes, identity, nonce string, ts int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	tss := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(CanonicalPayload(sub, roles, scopes, identity, tss, nonce))

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

// signCanonical signs whatever fields it is given, using the same canonical
// form the gateway uses. It exists so the tests below can hand the verifier a
// signature that is genuine for ONE identity and ask whether it authenticates
// ANOTHER.
func signCanonical(secret, sub, roles, scopes, identity, ts, nonce string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(CanonicalPayload(sub, roles, scopes, identity, ts, nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// A signature the gateway issued for one identity must not authenticate a
// different one.
//
// The payload used to be the six fields joined with ":", and none of them is
// constrained to exclude that byte — `sub` comes straight from a JWT claim. So
// a caller whose subject contained a colon received a signature equally valid
// for a different split of the same bytes, including one naming ANOTHER USER as
// the subject. Verified against the old encoding: a signature issued for
// sub="alice:admin" was accepted as sub="alice", roles="admin:".
//
// It matters wherever the backend is reachable without traversing the gateway —
// which is the only scenario this SDK exists for. If the backend could only be
// reached through AEGIS, CleanHeaders would be enough and nobody would verify
// anything.
func TestVerify_SignatureCannotBeResplitIntoAnotherIdentity(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	const nonce = "resplit-1"

	// Genuine signature for the attacker's own token.
	sig := signCanonical(testSecret, "alice:admin", "", "", "", ts, nonce)

	// Every re-split of those same bytes must be refused.
	for _, c := range []struct{ name, sub, roles string }{
		{"another subject entirely", "alice", "admin:"},
		{"subject truncated at the delimiter", "alice", "admin"},
		{"delimiter moved into roles", "alice:", "admin"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := New(testSecret, time.Minute, NewMemoryNonceStore())
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set(HeaderSubject, c.sub)
			r.Header.Set(HeaderRoles, c.roles)
			r.Header.Set(HeaderTimestamp, ts)
			r.Header.Set(HeaderNonce, nonce)
			r.Header.Set(HeaderSignature, sig)

			id, err := v.Verify(r)
			if err == nil {
				t.Fatalf("a signature issued for sub=%q authenticated sub=%q: impersonation",
					"alice:admin", id.Subject)
			}
		})
	}
}

// The genuine identity still verifies — the fix must not refuse a colon, only
// stop it moving a field boundary. Colons in subjects are ordinary (URNs,
// OIDC issuer-qualified ids), so rejecting them would have been a different bug.
func TestVerify_ASubjectMayContainTheDelimiter(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	const nonce = "resplit-2"
	sig := signCanonical(testSecret, "urn:user:alice", "admin", "read:orders", "7", ts, nonce)

	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderSubject, "urn:user:alice")
	r.Header.Set(HeaderRoles, "admin")
	r.Header.Set(HeaderScopes, "read:orders")
	r.Header.Set(HeaderIdentity, "7")
	r.Header.Set(HeaderTimestamp, ts)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderSignature, sig)

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("a legitimate colon-bearing subject was refused: %v", err)
	}
	if id.Subject != "urn:user:alice" || len(id.Scopes) != 1 || id.Scopes[0] != "read:orders" {
		t.Fatalf("identity came back wrong: %+v", id)
	}
}

// CanonicalPayload must be injective: distinct field tuples, distinct bytes.
// The old encoding failed exactly here.
func TestCanonicalPayload_IsInjective(t *testing.T) {
	tuples := [][]string{
		{"alice:admin", "", "", "", "1", "n"},
		{"alice", "admin:", "", "", "1", "n"},
		{"alice", "admin", "", "", "1", "n"},
		{"alice", "", "admin", "", "1", "n"},
		{"", "alice:admin", "", "", "1", "n"},
		{"a:b:c", "", "", "", "1", "n"},
		{"a", "b:c", "", "", "1", "n"},
		{"a:b", "c", "", "", "1", "n"},
	}
	seen := map[string][]string{}
	for _, tu := range tuples {
		got := string(CanonicalPayload(tu[0], tu[1], tu[2], tu[3], tu[4], tu[5]))
		if prev, dup := seen[got]; dup {
			t.Errorf("collision: %q and %q encode identically", prev, tu)
		}
		seen[got] = tu
	}
}

// A signature produced under the previous canonical form must fail closed, not
// be reinterpreted under the new one.
//
// During a rolling upgrade the gateway and some backends run different
// versions. The safe outcome is a rejected request — visible, fixed by
// finishing the rollout — rather than an old signature quietly satisfying the
// new verifier, which would leave the impersonation open for exactly as long as
// the rollout took.
//
// Note what this test does and does not prove: the length-prefixed encoding
// alone already differs from the old string, so this passes with or without
// PayloadVersion. The version prefix earns its place at the NEXT format
// change, when two length-prefixed encodings could otherwise be confused —
// which is not something a test can demonstrate today.
func TestVerify_RejectsASignatureFromThePreviousFormat(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	const nonce = "legacy-1"

	// The old encoding: the six fields joined with ":".
	legacy := strings.Join([]string{"alice", "admin", "", "", ts, nonce}, ":")
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(legacy))

	v := New(testSecret, time.Minute, NewMemoryNonceStore())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderSubject, "alice")
	r.Header.Set(HeaderRoles, "admin")
	r.Header.Set(HeaderTimestamp, ts)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderSignature, hex.EncodeToString(mac.Sum(nil)))

	if _, err := v.Verify(r); err == nil {
		t.Fatal("a signature from the previous canonical form was accepted")
	}
}
