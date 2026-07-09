// Package gatewayverify is the reference implementation backends use to verify
// the zero-trust identity AEGIS propagates downstream.
//
// AEGIS signs the authenticated identity it forwards so a backend can trust the
// `X-Gateway-*` headers only when they were produced by the gateway (and not
// injected by a client that reached the backend directly). The gateway computes:
//
//	payload   = subject ":" roles ":" scopes ":" identity ":" timestamp ":" nonce
//	signature = hex( HMAC-SHA256(shared_secret, payload) )
//
// and sets these request headers:
//
//	X-Gateway-Subject    the authenticated subject (JWT `sub`)
//	X-Gateway-Roles      comma-separated roles (may be empty)
//	X-Gateway-Scopes     OAuth2 scopes (may be empty)
//	X-Gateway-Identity   ownership-identity claim, e.g. a numeric uid (may be empty)
//	X-Gateway-Timestamp  unix seconds when the request was signed
//	X-Gateway-Nonce      per-request random nonce (hex)
//	X-Gateway-Signature  hex HMAC-SHA256 over the payload above
//
// A backend MUST verify all three properties before trusting the identity:
//
//  1. the HMAC matches (authenticity + integrity);
//  2. the timestamp is fresh (defends against replay of an old capture);
//  3. the nonce has not been seen before within the freshness window
//     (defends against replay within the freshness window).
//
// This package implements all three. Wire it as middleware via Handler, or call
// Verify directly. The shared secret is the gateway's `auth.secret`
// (AEGIS_JWT_SECRET) — keep it out of source and rotate it per the runbook.
package gatewayverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header names set by the gateway.
const (
	HeaderSubject   = "X-Gateway-Subject"
	HeaderRoles     = "X-Gateway-Roles"
	HeaderScopes    = "X-Gateway-Scopes"
	HeaderIdentity  = "X-Gateway-Identity"
	HeaderTimestamp = "X-Gateway-Timestamp"
	HeaderNonce     = "X-Gateway-Nonce"
	HeaderSignature = "X-Gateway-Signature"
)

// Errors returned by Verify. Callers should treat any non-nil error as "reject
// the request" — never fall back to trusting unverified headers.
var (
	ErrMissingHeaders = errors.New("gatewayverify: required X-Gateway-* headers missing")
	ErrBadTimestamp   = errors.New("gatewayverify: malformed timestamp")
	ErrStale          = errors.New("gatewayverify: signature timestamp outside freshness window")
	ErrBadSignature   = errors.New("gatewayverify: signature mismatch")
	ErrReplay         = errors.New("gatewayverify: nonce already seen (replay)")
)

// NonceStore records and checks nonces for replay protection. Implementations
// must be safe for concurrent use and should expire entries after at least the
// freshness window. SeenBefore records the nonce and reports whether it had
// already been recorded.
//
// For a single-process backend use NewMemoryNonceStore. For a horizontally
// scaled fleet, back this with a shared store (e.g. Redis SETNX with a TTL) so
// a replay cannot simply hit a different instance.
type NonceStore interface {
	SeenBefore(nonce string, ttl time.Duration) bool
}

// Identity is the verified caller identity extracted from the headers.
type Identity struct {
	Subject string
	Roles   []string
	Scopes  []string
	// Identity is the ownership-identity claim (X-Gateway-Identity), e.g. a
	// numeric user id used for object-ownership (BOLA) checks. Empty when the
	// gateway was not configured with an identity_claim. It is covered by the
	// signature, so a backend may trust it for authorization.
	Identity string
}

// HasRole reports whether the identity carries the given role.
func (id Identity) HasRole(role string) bool {
	for _, r := range id.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Verifier validates signed gateway identity headers.
type Verifier struct {
	secret    []byte
	freshness time.Duration
	nonces    NonceStore
}

// New creates a Verifier. secret is the gateway's shared auth secret. freshness
// is the maximum allowed clock skew between the gateway and the backend (the
// gateway signs with a 30s window; 60s is a safe default that tolerates minor
// skew). nonces records seen nonces for replay protection; pass
// NewMemoryNonceStore() if you don't have a shared store.
func New(secret string, freshness time.Duration, nonces NonceStore) *Verifier {
	if freshness <= 0 {
		freshness = 60 * time.Second
	}
	if nonces == nil {
		nonces = NewMemoryNonceStore()
	}
	return &Verifier{secret: []byte(secret), freshness: freshness, nonces: nonces}
}

// Verify validates the X-Gateway-* headers on r and returns the verified
// identity. A non-nil error means the request must be rejected.
func (v *Verifier) Verify(r *http.Request) (Identity, error) {
	sub := r.Header.Get(HeaderSubject)
	roles := r.Header.Get(HeaderRoles)
	scopes := r.Header.Get(HeaderScopes)
	identity := r.Header.Get(HeaderIdentity)
	ts := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	sig := r.Header.Get(HeaderSignature)

	if sub == "" || ts == "" || nonce == "" || sig == "" {
		return Identity{}, ErrMissingHeaders
	}

	// 1. Freshness — reject before doing crypto on obviously stale requests.
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return Identity{}, ErrBadTimestamp
	}
	signedAt := time.Unix(secs, 0)
	if skew := time.Since(signedAt); skew > v.freshness || skew < -v.freshness {
		return Identity{}, ErrStale
	}

	// 2. Authenticity — constant-time HMAC comparison over the canonical payload.
	payload := strings.Join([]string{sub, roles, scopes, identity, ts, nonce}, ":")
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)

	got, err := hex.DecodeString(sig)
	if err != nil || subtle.ConstantTimeCompare(got, expected) != 1 {
		return Identity{}, ErrBadSignature
	}

	// 3. Replay — record the nonce last, only after the signature is trusted, so
	// an attacker cannot exhaust the store with forged nonces.
	if v.nonces.SeenBefore(nonce, v.freshness*2) {
		return Identity{}, ErrReplay
	}

	id := Identity{Subject: sub, Identity: identity}
	if roles != "" {
		id.Roles = strings.Split(roles, ",")
	}
	if scopes != "" {
		id.Scopes = strings.Fields(scopes)
	}
	return id, nil
}

// identityContextKey is the type used to store the verified identity in the
// request context.
type identityContextKey struct{}

// FromContext returns the identity stored by Handler, if any.
func FromContext(r *http.Request) (Identity, bool) {
	id, ok := r.Context().Value(identityContextKey{}).(Identity)
	return id, ok
}

// Handler wraps next, verifying the gateway identity on every request. On
// failure it responds 401 and does not call next. On success it stores the
// verified Identity in the request context (retrieve it with FromContext).
func (v *Verifier) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := v.Verify(r)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := contextWithIdentity(r, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
