package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
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
	cfg     config.AuthConfig
	log     Logger
	st      Store
	jwks    keyfunc.Keyfunc
	jwksMu  sync.RWMutex
}

// NewJWTAuth creates a new JWT authentication middleware instance.
// If JWKS URL is configured, it fetches public keys for RSA/ECDSA validation.
// Otherwise, falls back to HMAC shared-secret validation.
func NewJWTAuth(cfg config.AuthConfig, log Logger, st Store) *JWTAuth {
	ja := &JWTAuth{cfg: cfg, log: log, st: st}

	if cfg.JWKSURL != "" {
		go ja.initJWKS()
	}

	return ja
}

// initJWKS fetches and caches JWKS keys from the configured URL.
// Retries on failure with exponential backoff.
func (ja *JWTAuth) initJWKS() {
	var backoff time.Duration = 2 * time.Second

	for attempt := 1; attempt <= 5; attempt++ {
		k, err := keyfunc.NewDefault([]string{ja.cfg.JWKSURL})
		if err != nil {
			ja.log.Error("jwks: fetch failed", map[string]any{
				"url":     ja.cfg.JWKSURL,
				"attempt": attempt,
				"error":   err.Error(),
			})
			time.Sleep(backoff)
			backoff *= 2
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

	ja.log.Error("jwks: all fetch attempts failed, JWKS validation unavailable", map[string]any{
		"url": ja.cfg.JWKSURL,
	})
}

// keyFunc returns the appropriate key function based on configuration.
// Priority: JWKS URL (RSA/ECDSA) > Shared Secret (HMAC)
func (ja *JWTAuth) keyFunc(token *jwt.Token) (any, error) {
	// If JWKS is configured and loaded, use it for RSA/ECDSA
	ja.jwksMu.RLock()
	jwks := ja.jwks
	ja.jwksMu.RUnlock()

	if jwks != nil {
		// Validate that the algorithm is an asymmetric type
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA, *jwt.SigningMethodRSAPSS:
			return jwks.KeyfuncCtx(context.Background())(token)
		default:
			// Reject HMAC tokens when JWKS is configured (prevents downgrade attacks)
			return nil, jwt.ErrSignatureInvalid
		}
	}

	// Fallback: HMAC shared secret
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
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
			// Check if path is excluded
			for _, ex := range ja.cfg.Exclude {
				if strings.HasPrefix(r.URL.Path, ex) {
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

			// Parse and validate using the appropriate key function
			token, err := jwt.Parse(tokenStr, ja.keyFunc)
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
				found := false
				for _, audValue := range aud {
					if audValue == ja.cfg.Audience {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, "Invalid Audience", http.StatusUnauthorized)
					return
				}
			}

			// Check JTI revocation (token blacklist)
			if jti, ok := claims["jti"].(string); ok && jti != "" {
				revoked, err := ja.st.IsJTIRevoked(r.Context(), jti)
				if err != nil {
					ja.log.Error("jwt_revocation_check_failed", map[string]any{"error": err.Error()})
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

			// Zero-Trust Identity Propagation
			// Use HMAC-signed header to prevent upstream spoofing
			if sub, ok := claims["sub"].(string); ok {
				r.Header.Set("X-Gateway-Subject", sub)
				// Sign subject header so upstream can verify it came from gateway
				if ja.cfg.Secret != "" {
					mac := hmac.New(sha256.New, []byte(ja.cfg.Secret))
					mac.Write([]byte(sub))
					r.Header.Set("X-Gateway-Signature", hex.EncodeToString(mac.Sum(nil)))
				}
			}
			if roles, ok := claims["roles"].([]any); ok {
				roleStrs := make([]string, 0, len(roles))
				for _, role := range roles {
					if s, ok := role.(string); ok {
						roleStrs = append(roleStrs, s)
					}
				}
				r.Header.Set("X-Gateway-Roles", strings.Join(roleStrs, ","))
			}

			// Propagate scopes for OAuth2 compatibility
			if scope, ok := claims["scope"].(string); ok {
				r.Header.Set("X-Gateway-Scopes", scope)
			}

			// Store authenticated subject in context
			ctx := context.WithValue(r.Context(), ctxKeySubject, claims["sub"])
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type contextKey string

const ctxKeySubject contextKey = "gateway.subject"
