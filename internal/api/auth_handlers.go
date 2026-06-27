package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/middleware"
	"api-gateway/internal/tenant"
)

// loginBruteforceLimit is the per-IP cap of /api/login failures within
// loginBruteforceWindow. Eight tries in five minutes is generous for an
// operator who fat-fingered their password but well below the rate a credential
// stuffer would need. The counter only increments on FAILURE; a successful
// login does not consume budget.
const (
	loginBruteforceLimit  = 8
	loginBruteforceWindow = 5 * time.Minute
)

// randToken returns a cryptographically random hex token.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// login authenticates the console and establishes a server-side session. Two
// credential forms are accepted, both via the same endpoint:
//
//   - {"secret": "..."} — legacy/bootstrap: matches AEGIS_ADMIN_SECRET; produces
//     a super-admin session bound to the default tenant. Kept for CLI/CI and
//     first-boot bootstrap when no users exist yet.
//   - {"email": "...", "password": "...", "tenant": "..."} — real per-tenant
//     operator login. Looked up in the iam user store; the session carries the
//     user's tenant + role and AdminAuth threads them into request context so
//     every admin endpoint is automatically scoped.
//
// The session token is delivered as an HttpOnly cookie (so JS — and therefore
// any XSS — cannot read it); the bound CSRF token is returned in the body for
// the client to echo on state-changing requests.
//
// POST /api/login
func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.AdminAuth {
		writeJSON(w, http.StatusOK, map[string]any{"csrf": "", "auth": false})
		return
	}
	// Per-IP brute-force gate. We check the failure counter BEFORE doing any
	// crypto work, so flooders are turned away cheaply. The counter is only
	// bumped on an actual failure below — successful operators never spend
	// budget.
	ip := middleware.RealIP(r)
	if n, err := h.store.GetRate(r.Context(), "loginfail:"+ip); err == nil && n >= int64(loginBruteforceLimit) {
		h.store.IncrMetric(r.Context(), "blocked_admin_login_throttled")
		w.Header().Set("Retry-After", strconv.Itoa(int(loginBruteforceWindow.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}
	var req struct {
		Secret   string `json:"secret"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Tenant   string `json:"tenant"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	fail := func(method, tnt string) {
		_, _ = h.store.IncrRate(r.Context(), "loginfail:"+ip, loginBruteforceWindow)
		h.store.IncrMetric(r.Context(), "blocked_admin_login_failed")
		fields := map[string]any{"ip": ip, "method": method}
		if tnt != "" {
			fields["tenant"] = tnt
		}
		h.log.Warn("admin_login_failed", fields)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
	}

	var sess iam.Session
	switch {
	case req.Secret != "":
		if subtle.ConstantTimeCompare([]byte(req.Secret), []byte(h.cfg.AdminSecret)) != 1 {
			fail("secret", "")
			return
		}
		// Bearer secret is the bootstrap super-admin: pinned to the default
		// tenant, granted SuperAdmin so it can manage tenants/users when no
		// real users exist yet.
		sess = iam.Session{TenantID: tenant.Default, Role: iam.RoleAdmin, SuperAdmin: true}

	case req.Email != "" && req.Password != "":
		if h.users == nil {
			// No user store wired (forensic_dsn not configured); only secret
			// login is available.
			writeError(w, http.StatusServiceUnavailable, "user login is not configured")
			return
		}
		tid := strings.TrimSpace(req.Tenant)
		if tid == "" {
			tid = tenant.Default
		}
		u, err := h.users.VerifyPassword(r.Context(), tid, req.Email, req.Password)
		if err != nil || u.ID == "" {
			// Same error string regardless of cause: do not reveal whether the
			// tenant/email exists. (iam.ErrUserNotFound is the typical err;
			// any other DB error is also treated as a credential failure so
			// callers cannot distinguish.)
			fail("password", tid)
			return
		}
		sess = iam.Session{
			TenantID:   u.TenantID,
			Role:       u.Role,
			UserID:     u.ID,
			Email:      u.Email,
			SuperAdmin: u.SuperAdmin,
		}

	default:
		writeError(w, http.StatusBadRequest, "supply either {secret} or {email,password}")
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
	sess.CSRF = csrf
	if err := h.store.CreateSession(r.Context(), sessionTok, sess, h.cfg.AdminSessionTTL); err != nil {
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
	h.log.Info("admin_login", map[string]any{
		"ip":     middleware.RealIP(r),
		"tenant": sess.TenantID,
		"role":   string(sess.Role),
		"user":   sess.UserID,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"csrf":   csrf,
		"auth":   true,
		"tenant": sess.TenantID,
		"role":   string(sess.Role),
	})
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
