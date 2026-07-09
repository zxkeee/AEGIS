package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"api-gateway/internal/config"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// JWTAuth validates JWT tokens and propagates identity downstream.
// Supports both HMAC (shared secret) and RSA/ECDSA (JWKS URL) validation.
type JWTAuth struct {
	cfg    config.AuthConfig
	log    Logger
	st     RevocationChecker
	jwks   keyfunc.Keyfunc
	jwksMu sync.RWMutex
}

// NewJWTAuth creates a new JWT authentication middleware instance.
// If JWKS URL is configured, it fetches public keys for RSA/ECDSA validation.
// Otherwise, falls back to HMAC shared-secret validation.
func NewJWTAuth(cfg config.AuthConfig, log Logger, st RevocationChecker) *JWTAuth {
	ja := &JWTAuth{cfg: cfg, log: log, st: st}

	if cfg.JWKSURL != "" {
		go ja.initJWKS()
	}

	return ja
}

// jwksMaxBackoff caps the retry interval of the background JWKS fetch loop.
const jwksMaxBackoff = 5 * time.Minute

// initJWKS fetches and caches JWKS keys from the configured URL, retrying
// FOREVER with capped exponential backoff. Validation fails closed while the
// keys are absent (see keyFunc), so giving up after a fixed number of attempts
// — as this used to — turned a transient IdP outage at gateway boot into a
// permanent 401 for all traffic until a manual restart. Once the initial fetch
// succeeds, keyfunc refreshes keys in the background on its own.
func (ja *JWTAuth) initJWKS() {
	backoff := 2 * time.Second

	for attempt := 1; ; attempt++ {
		k, err := keyfunc.NewDefault([]string{ja.cfg.JWKSURL})
		if err != nil {
			ja.log.Error("jwks: fetch failed (all tokens are rejected until keys load); will retry", map[string]any{
				"url":      ja.cfg.JWKSURL,
				"attempt":  attempt,
				"retry_in": backoff.String(),
				"error":    err.Error(),
			})
			time.Sleep(backoff)
			if backoff *= 2; backoff > jwksMaxBackoff {
				backoff = jwksMaxBackoff
			}
			continue
		}

		ja.jwksMu.Lock()
		ja.jwks = k
		ja.jwksMu.Unlock()

		ja.log.Info("jwks: keys loaded successfully", map[string]any{
			"url": ja.cfg.JWKSURL,
		})
		return
	}
}

// keyFunc returns the appropriate key function based on configuration.
// Priority: JWKS URL (RSA/ECDSA) > Shared Secret (HMAC)
func (ja *JWTAuth) keyFunc(token *jwt.Token) (any, error) {
	// If JWKS is configured and loaded, use it for RSA/ECDSA
	ja.jwksMu.RLock()
	jwks := ja.jwks
	ja.jwksMu.RUnlock()

	// When a JWKS URL is configured we must NEVER fall back to HMAC, even if the
	// keys have not finished loading yet (async init) or all fetch attempts have
	// failed. Falling back would let an attacker forge HMAC tokens — trivially so
	// if the shared secret is empty (the common case when JWKS is used). Fail
	// closed: reject every token until JWKS is available.
	if ja.cfg.JWKSURL != "" {
		if jwks == nil {
			return nil, fmt.Errorf("jwks keys not loaded yet")
		}
		// Validate that the algorithm is an asymmetric type
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA, *jwt.SigningMethodRSAPSS:
			return jwks.KeyfuncCtx(context.Background())(token)
		default:
			// Reject HMAC tokens when JWKS is configured (prevents downgrade attacks)
			return nil, jwt.ErrSignatureInvalid
		}
	}

	// HMAC shared secret mode (only when no JWKS URL is configured).
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, jwt.ErrSignatureInvalid
	}
	if ja.cfg.Secret == "" {
		// Never accept tokens signed with an empty HMAC key.
		return nil, jwt.ErrSignatureInvalid
	}
	return []byte(ja.cfg.Secret), nil
}

// Middleware returns the HTTP middleware function.
func (ja *JWTAuth) Middleware() Middleware {
	if !ja.cfg.Enabled {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is excluded (segment-boundary match, so "/public"
			// excludes "/public" and "/public/x" but not "/publicXYZ").
			for _, ex := range ja.cfg.Exclude {
				if config.PathHasPrefix(r.URL.Path, ex) {
					next.ServeHTTP(w, r)
					return
				}
			}

			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(auth, "Bearer ")

			// Parse and validate using the appropriate key function.
			// WithExpirationRequired rejects tokens that carry no "exp" claim:
			// golang-jwt does not require one by default, which would let a signed
			// token live forever. A security gateway must enforce expiry.
			token, err := jwt.Parse(tokenStr, ja.keyFunc, jwt.WithExpirationRequired())
			if err != nil || !token.Valid {
				errMsg := "unknown"
				if err != nil {
					errMsg = err.Error()
				}
				ja.log.Warn("jwt_invalid", map[string]any{
					"ip":    RealIP(r),
					"error": errMsg,
				})
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
				return
			}

			// Extract claims
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "Invalid Claims", http.StatusUnauthorized)
				return
			}

			// Validate Issuer if configured
			if ja.cfg.Issuer != "" {
				iss, _ := claims.GetIssuer()
				if iss != ja.cfg.Issuer {
					http.Error(w, "Invalid Issuer", http.StatusUnauthorized)
					return
				}
			}

			// Validate Audience
			if ja.cfg.Audience != "" {
				aud, _ := claims.GetAudience()
				if !slices.Contains(aud, ja.cfg.Audience) {
					http.Error(w, "Invalid Audience", http.StatusUnauthorized)
					return
				}
			}

			// Check JTI revocation (token blacklist)
			if jti, ok := claims["jti"].(string); ok && jti != "" {
				revoked, err := ja.st.IsJTIRevoked(r.Context(), jti)
				if err != nil {
					ja.log.Error("jwt_revocation_check_failed", map[string]any{
						"error":       err.Error(),
						"fail_closed": ja.cfg.RevocationFailClosed,
					})
					// On a backing-store outage the revocation status is unknown. By
					// default we fail open (proceed) to preserve availability; in
					// high-assurance mode we deny so a revoked token can never slip
					// through during an outage.
					if ja.cfg.RevocationFailClosed {
						http.Error(w, "Token Revocation Check Unavailable", http.StatusServiceUnavailable)
						return
					}
				}
				if revoked {
					ja.log.Warn("jwt_revoked_token_used", map[string]any{
						"jti": jti,
						"ip":  RealIP(r),
					})
					http.Error(w, "Token Revoked", http.StatusUnauthorized)
					return
				}
			}

			// Zero-Trust Identity Propagation.
			// Collect the identity we forward downstream first, then sign ALL of it
			// (subject + roles + scopes) together with a timestamp and a per-request
			// nonce. Signing only the subject (as before) left roles/scopes
			// unauthenticated and the signature replayable. Upstream must verify:
			//   1. HMAC over "sub:roles:scopes:ts:nonce" matches X-Gateway-Signature
			//   2. abs(now - ts) < 30s   (freshness)
			//   3. nonce has not been seen before within the freshness window (replay)
			sub, _ := claims["sub"].(string)
			if sub != "" {
				r.Header.Set("X-Gateway-Subject", sub)
			}

			var roleStr string
			if roles, ok := claims["roles"].([]any); ok {
				roleStrs := make([]string, 0, len(roles))
				for _, role := range roles {
					if s, ok := role.(string); ok {
						roleStrs = append(roleStrs, s)
					}
				}
				roleStr = strings.Join(roleStrs, ",")
				r.Header.Set("X-Gateway-Roles", roleStr)
			}

			// Propagate scopes for OAuth2 compatibility.
			scopeStr, _ := claims["scope"].(string)
			if scopeStr != "" {
				r.Header.Set("X-Gateway-Scopes", scopeStr)
			}

			// Propagate a configurable ownership-identity claim (X-Gateway-Identity)
			// so BOLA ownership detection can compare the resource owner in a
			// response body against the caller's real id even when it is not `sub`.
			// CleanHeaders strips any inbound X-Gateway-* so this cannot be forged.
			// The value is also folded into the signed payload below so a backend
			// (via the gatewayverify SDK) can authenticate it, not just the gateway.
			var identityStr string
			if ja.cfg.IdentityClaim != "" {
				if id := claimToString(claims[ja.cfg.IdentityClaim]); id != "" {
					identityStr = id
					r.Header.Set("X-Gateway-Identity", id)
				}
			}

			// Identity-propagation signing key. Prefer the dedicated
			// propagation_secret (works for both JWKS and HMAC token verification
			// modes); fall back to the HMAC token secret for backward
			// compatibility with single-secret installs. Without either, the
			// signature is skipped and backends will reject the request via the
			// gatewayverify SDK — which is the right fail-closed behaviour.
			propSecret := ja.cfg.PropagationSecret
			if propSecret == "" {
				propSecret = ja.cfg.Secret
			}
			if sub != "" && propSecret != "" {
				ts := fmt.Sprintf("%d", time.Now().Unix())
				nonceBytes := make([]byte, 16)
				// A failed read would yield an all-zero (predictable) nonce, which
				// weakens replay defence. crypto/rand failing is catastrophic and
				// practically never happens, but fail closed: skip signing so the
				// backend's gatewayverify SDK rejects the request rather than trust
				// a weak nonce.
				if _, err := rand.Read(nonceBytes); err != nil {
					ja.log.Error("jwt: identity nonce generation failed; skipping signature", map[string]any{
						"error": err.Error(),
					})
				} else {
					nonce := hex.EncodeToString(nonceBytes)

					// Canonical payload — upstream must reconstruct it identically.
					// identityStr is included so the ownership claim is authenticated,
					// not just the gateway-internal header (which a backend reachable
					// directly could otherwise be tricked into trusting).
					payload := strings.Join([]string{sub, roleStr, scopeStr, identityStr, ts, nonce}, ":")
					mac := hmac.New(sha256.New, []byte(propSecret))
					mac.Write([]byte(payload))

					r.Header.Set("X-Gateway-Timestamp", ts)
					r.Header.Set("X-Gateway-Nonce", nonce)
					r.Header.Set("X-Gateway-Signature", hex.EncodeToString(mac.Sum(nil)))
				}
			}

			// Enrich the discovery observation with the verified identity so the
			// catalog can attribute this call to a consumer and mark it authenticated.
			if obs := observationFrom(r.Context()); obs != nil {
				obs.AuthPresent = true
				obs.ConsumerSubject = sub
			}

			// Store authenticated subject in context
			ctx := context.WithValue(r.Context(), ctxKeySubject, claims["sub"])
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type contextKey string

const ctxKeySubject contextKey = "gateway.subject"

// claimToString renders a JWT claim value as a string for identity comparison.
// JSON numbers arrive as float64 from MapClaims; format them without a trailing
// ".000000" so a numeric id like 42 compares cleanly against a body field.
func claimToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}
