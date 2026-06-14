package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"time"

	"api-gateway/internal/middleware"
)

// randToken returns a cryptographically random hex token.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// login authenticates the console with the admin secret and establishes a
// server-side session. The session token is delivered as an HttpOnly cookie (so
// JavaScript — and therefore any XSS — cannot read it); the bound CSRF token is
// returned in the body for the client to echo on state-changing requests.
//
// POST /api/login  {"secret": "..."}  ->  {"csrf": "..."}
func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.AdminAuth {
		writeJSON(w, http.StatusOK, map[string]any{"csrf": "", "auth": false})
		return
	}
	var req struct {
		Secret string `json:"secret"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Secret), []byte(h.cfg.AdminSecret)) != 1 {
		// Record the failed attempt for visibility/brute-force monitoring.
		h.store.IncrMetric(r.Context(), "blocked_admin_login_failed")
		h.log.Warn("admin_login_failed", map[string]any{"ip": middleware.RealIP(r)})
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	sessionTok, err := randToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	csrf, err := randToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	if err := h.store.CreateSession(r.Context(), sessionTok, csrf, h.cfg.AdminSessionTTL); err != nil {
		h.log.Error("admin: create session failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}

	secure := !h.cfg.AdminCookieInsecure
	maxAge := int(h.cfg.AdminSessionTTL / time.Second)
	// Session cookie: HttpOnly so JS/XSS cannot read or exfiltrate it. Secure is
	// on by default; only dropped via the explicit admin_cookie_insecure dev flag.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure default on; SameSite=Strict; HttpOnly set
		Name:     middleware.SessionCookie,
		Value:    sessionTok,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
	// CSRF cookie: readable by the console JS for the double-submit pattern. It is
	// useless to a cross-site attacker (same-origin policy hides it) and useless
	// without the HttpOnly session cookie.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- CSRF double-submit token; Secure default on; SameSite=Strict
		Name:     middleware.CSRFCookie,
		Value:    csrf,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
	h.log.Info("admin_login", map[string]any{"ip": middleware.RealIP(r)})
	writeJSON(w, http.StatusOK, map[string]any{"csrf": csrf, "auth": true})
}

// logout invalidates the current session and clears the cookie.
// POST /api/logout
func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(middleware.SessionCookie); err == nil && c.Value != "" {
		_ = h.store.DeleteSession(r.Context(), c.Value)
	}
	secure := !h.cfg.AdminCookieInsecure
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- session cookie cleared (logout)
		Name: middleware.SessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- CSRF cookie cleared (logout)
		Name: middleware.CSRFCookie, Value: "", Path: "/",
		HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}
