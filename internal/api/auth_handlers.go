package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api-gateway/internal/audit"
	"api-gateway/internal/iam"
	"api-gateway/internal/middleware"
	"api-gateway/internal/tenant"
)

// loginBruteforceLimit is the per-IP cap of /api/login failures within
// loginBruteforceWindow. Eight tries in five minutes is generous for an
// operator who fat-fingered their password but well below the rate a credential
// stuffer would need. The counter only increments on FAILURE; a successful
// login does not consume budget.
//
// accountBruteforceLimit/Window is the SAME budget applied per (tenant,email)
// instead of per-IP. The per-IP gate alone does not stop a distributed
// attacker (botnet / residential proxy pool) targeting one known account:
// each guess can arrive from a fresh IP and never trips the IP counter. This
// second, independent gate closes that gap regardless of how many source IPs
// are used.
const (
	loginBruteforceLimit  = 8
	loginBruteforceWindow = 5 * time.Minute

	accountBruteforceLimit  = 8
	accountBruteforceWindow = 5 * time.Minute
)

// accountLoginKey builds the per-account brute-force counter key. Email is
// lower-cased to match VerifyPassword's case-insensitive lookup, so
// "User@x.com" and "user@x.com" share one budget rather than doubling it.
func accountLoginKey(tenantID, email string) string {
	return "loginfail:acct:" + tenantID + ":" + strings.ToLower(strings.TrimSpace(email))
}

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
	// Per-IP brute-force gate. Reserve a slot atomically (IncrRate) BEFORE doing
	// any credential-checking work, rather than reading the counter and
	// deciding separately: a read-then-decide split lets concurrent requests
	// all observe the same under-limit count and all proceed, since none of
	// them has incremented yet by the time the others check — the increment
	// below is a single atomic Redis operation, so at most loginBruteforceLimit
	// concurrent+sequential attempts can ever get past this gate in a window,
	// no matter how many arrive at once. A successful login refunds its slot
	// via DecrRate below, preserving "only failures spend budget."
	ip := middleware.RealIP(r)
	n, err := h.store.IncrRate(r.Context(), "loginfail:"+ip, loginBruteforceWindow)
	if err != nil {
		// Redis unavailable: the gate cannot enforce its budget. Default is
		// fail-open (preserve availability — a legitimate operator can still
		// log in during an outage); AdminLoginFailClosed denies instead, for
		// deployments where an unthrottled /api/login during a Redis outage
		// is not acceptable.
		h.log.Error("login: brute-force store unavailable", map[string]any{
			"error": err.Error(), "fail_closed": h.cfg.AdminLoginFailClosed,
		})
		if h.cfg.AdminLoginFailClosed {
			h.store.IncrMetric(r.Context(), "blocked_admin_login_store_unavailable")
			writeError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
			return
		}
	} else if n > int64(loginBruteforceLimit) {
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
		// The slot was already reserved atomically above; a failure just keeps it
		// spent (nothing to do here beyond the metric/audit/log below).
		h.store.IncrMetric(r.Context(), "blocked_admin_login_failed")
		fields := map[string]any{"ip": ip, "method": method}
		if tnt != "" {
			fields["tenant"] = tnt
		}
		h.log.Warn("admin_login_failed", fields)
		h.audit.Record(audit.Entry{
			TenantID: tnt, ActorEmail: req.Email, Action: "login_failed",
			Method: r.Method, Path: r.URL.Path, Status: http.StatusUnauthorized,
			IP: ip, Detail: method,
		})
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
		// Per-account brute-force gate, independent of the per-IP one above.
		// Same atomic-reserve-before-work pattern: a distributed attacker
		// rotating source IPs against this one account still exhausts this
		// budget, since it's keyed by (tenant, email) rather than IP.
		acctKey := accountLoginKey(tid, req.Email)
		an, aerr := h.store.IncrRate(r.Context(), acctKey, accountBruteforceWindow)
		if aerr != nil {
			// Same fail-open/fail-closed choice as the per-IP gate above — see
			// its comment. A Redis outage must not silently drop BOTH gates
			// when AdminLoginFailClosed asks for the stronger behaviour.
			h.log.Error("login: account brute-force store unavailable", map[string]any{
				"error": aerr.Error(), "fail_closed": h.cfg.AdminLoginFailClosed,
			})
			if h.cfg.AdminLoginFailClosed {
				h.store.IncrMetric(r.Context(), "blocked_admin_login_store_unavailable")
				writeError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
				return
			}
		} else if an > int64(accountBruteforceLimit) {
			h.store.IncrMetric(r.Context(), "blocked_admin_login_throttled_account")
			w.Header().Set("Retry-After", strconv.Itoa(int(accountBruteforceWindow.Seconds())))
			writeError(w, http.StatusTooManyRequests, "too many failed login attempts for this account; try again later")
			return
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
		// Credentials checked out: refund the account slot too (mirrors the
		// per-IP refund below), so a successful login never spends either budget.
		h.store.DecrRate(r.Context(), acctKey)
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

	// Credentials checked out: refund the slot reserved above so a successful
	// login never spends brute-force budget, per the documented contract.
	h.store.DecrRate(r.Context(), "loginfail:"+ip)

	csrf, err := h.establishSession(r.Context(), w, sess)
	if err != nil {
		h.log.Error("admin: create session failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	h.audit.Record(audit.Entry{
		TenantID: sess.TenantID, ActorID: sess.UserID, ActorEmail: sess.Email,
		Role: string(sess.Role), SuperAdmin: sess.SuperAdmin, Action: "login",
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, IP: ip,
	})
	h.log.Info("admin_login", map[string]any{
		"ip":     middleware.RealIP(r),
		"tenant": sess.TenantID,
		"role":   string(sess.Role),
		"user":   sess.UserID,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"csrf":        csrf,
		"auth":        true,
		"tenant":      sess.TenantID,
		"role":        string(sess.Role),
		"super_admin": sess.SuperAdmin,
	})
}

// establishSession mints the session + CSRF tokens, persists the server-side
// session, and sets the two cookies. Shared by password login (which returns
// the CSRF in a JSON body) and the OIDC callback (which redirects). Returns the
// CSRF token so the caller can surface it. sess.CSRF is populated here.
func (h *handlers) establishSession(ctx context.Context, w http.ResponseWriter, sess iam.Session) (string, error) {
	sessionTok, err := randToken()
	if err != nil {
		return "", err
	}
	csrf, err := randToken()
	if err != nil {
		return "", err
	}
	sess.CSRF = csrf
	if err := h.store.CreateSession(ctx, sessionTok, sess, h.cfg.AdminSessionTTL); err != nil {
		return "", err
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
	return csrf, nil
}

// logout invalidates the current session and clears the cookie.
// POST /api/logout
// GET /api/session — the caller's own tenant/role/super-admin flag, read
// straight from the request context AdminAuth already populated. The console
// calls this on every load to rehydrate who's signed in (the login response
// is only seen once, at login time, and doesn't survive a page refresh).
func (h *handlers) getSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant":      tenant.From(r.Context()),
		"role":        string(iam.FromContext(r.Context())),
		"super_admin": iam.IsSuperAdmin(r.Context()),
	})
}

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
