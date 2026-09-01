package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"api-gateway/internal/config"
)

// ConsumerID gives a caller a stable identity when it presents an opaque
// credential rather than a JWT.
//
// Why this exists
// ---------------
// Everything identity-aware in AEGIS reads the verified JWT subject. BOLA and
// BFLA are "did THIS consumer read an object it does not own", the catalog's
// consumer graph is "who calls what", and the findings say "N requests arrived
// without authentication". With no JWT, every caller collapses into one
// "ip:<addr>" consumer.
//
// That is not an edge case. Pointed at a live Forgejo, the whole run recorded a
// single consumer covering 152 endpoints, and the flagship detection could not
// fire at all (assessment, 2026-08-31). Opaque bearer tokens, API keys and
// session cookies are how most APIs actually authenticate; requiring a customer
// to migrate to JWTs before AEGIS can see anything is not a product, it is a
// prerequisite nobody agreed to.
//
// What it does
// ------------
// When no JWT subject was established, it looks for a credential the caller
// supplied — a bearer token that is not a JWT, a configured API-key header, or a
// configured session cookie — and derives a stable pseudonymous id from it. Two
// requests carrying the same credential get the same id; two different callers
// never collide. That is all object-ownership detection needs: it compares
// identities for equality and never interprets them.
//
// The credential itself is never stored, logged or forwarded. The id is
// HMAC-SHA256 over it, truncated, and a bare hash would not be enough — API keys
// and session ids are drawn from small enough spaces that anyone with read
// access to the catalog could search a plain digest back to a live credential
// and then impersonate that caller. The key makes that impossible without also
// holding the deployment's secret.
//
// It runs AFTER JWT auth, so a verified subject always wins: a JWT carries a
// real, meaningful identity, and a pseudonym derived from the same request would
// only split one caller across two consumer records.
func ConsumerID(cfg config.ConsumerIDConfig, secret string) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	headers := make([]string, 0, len(cfg.Headers))
	for _, h := range cfg.Headers {
		if h = strings.TrimSpace(h); h != "" {
			headers = append(headers, h)
		}
	}
	cookies := make([]string, 0, len(cfg.Cookies))
	for _, c := range cfg.Cookies {
		if c = strings.TrimSpace(c); c != "" {
			cookies = append(cookies, c)
		}
	}
	key := []byte(secret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A verified JWT subject is a better identity than any pseudonym.
			if r.Header.Get("X-Gateway-Subject") != "" {
				next.ServeHTTP(w, r)
				return
			}

			cred := opaqueCredential(r, headers, cookies)
			if cred == "" {
				next.ServeHTTP(w, r)
				return
			}

			id := pseudonym(key, cred)
			// The header is internal: CleanHeaders strips any inbound X-Gateway-*
			// before this runs, so a client cannot present its own.
			r.Header.Set("X-Gateway-Consumer-Key", id)
			if obs := observationFrom(r.Context()); obs != nil {
				obs.ConsumerKey = id
			}
			next.ServeHTTP(w, r)
		})
	}
}

// opaqueCredential returns the first credential the request carries, or "".
// Order is deliberate: an Authorization header is a stronger statement of
// identity than a cookie, which browsers attach to every request whether the
// caller meant to authenticate or not.
func opaqueCredential(r *http.Request, headers, cookies []string) string {
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		scheme, value, found := strings.Cut(auth, " ")
		value = strings.TrimSpace(value)
		if found && value != "" {
			switch strings.ToLower(scheme) {
			case "bearer":
				// A JWT here means auth is enabled but this token failed
				// verification, or the route does not require auth and it was
				// only identified. Either way the subject header is empty and we
				// must not mint a pseudonym from a token whose claims are
				// unverified — that would let a caller manufacture identities at
				// will by varying a signature.
				if !looksLikeJWT(value) {
					return value
				}
			case "basic", "token", "apikey":
				return value
			}
		}
	}
	for _, h := range headers {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	for _, name := range cookies {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// looksLikeJWT reports whether s has the three base64url segments of a JWS. It
// is a shape check, not verification — verification is the JWT middleware's job,
// and the point here is only to leave those tokens alone.
func looksLikeJWT(s string) bool {
	first := strings.IndexByte(s, '.')
	if first <= 0 {
		return false
	}
	second := strings.IndexByte(s[first+1:], '.')
	return second > 0 && strings.IndexByte(s[first+1+second+1:], '.') < 0
}

// pseudonym derives the stable id. Truncated to 16 hex characters: 64 bits is
// far beyond collision range for any realistic number of consumers, and a short
// id keeps the console readable, where it appears as "token:<id>".
func pseudonym(key []byte, cred string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(cred))
	return "token:" + hex.EncodeToString(m.Sum(nil))[:16]
}
