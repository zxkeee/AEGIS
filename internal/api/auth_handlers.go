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

// bootstrapSecretLoginKey is the fixed telemetry counter key for the
// {"secret": ...} bootstrap-login path (VULN-802 — see the observe-only
// comment at its use site for why this counts failures but never blocks on
// them, unlike accountLoginKey below).
//
// bootstrapSecretBruteforceLimit/Window are deliberately NOT the same as
// accountBruteforceLimit/Window (VULN-901/902 fix): that budget was sized for
// one attacker against one (tenant, email) account. This counter is shared by
// every unauthenticated caller of the bootstrap path across every source IP —
// reusing the per-account number made the alert fire on completely ordinary
// multi-source legitimate traffic (a handful of CI jobs, engineers, or health
// checks hitting /api/login within the same window). A higher limit over a
// longer window still catches a sustained/distributed guessing campaign
// (which needs to sit in this window continuously to matter, given the
// secret's entropy) while giving realistic legitimate concurrent bootstrap
// usage room to not trip it.
const (
	bootstrapSecretLoginKey         = "loginfail:acct:__bootstrap_secret__" // #nosec G101 -- a Redis counter key name, not a credential
	bootstrapSecretBruteforceLimit  = 40
	bootstrapSecretBruteforceWindow = 15 * time.Minute
)

// bootstrapSecretDelaySemaphore bounds how many {"secret": ...} login
// requests can be HOLDING a bootstrapSecretDelay slot concurrently.
//
// This is the fix for the gap a security review found in the first version
// of this throttle: a per-request time.Sleep only taxes LATENCY, not attacker
// THROUGHPUT — by Little's Law, rate ≈ concurrency / latency, so an attacker
// willing to open enough concurrent connections routes around any fixed
// per-request delay for free (a botnet at, say, 10,000 concurrent connections
// sees just as many guesses/sec through a 3s delay as a single-threaded
// attacker saw with no delay at all). A semaphore turns the ladder into what
// actually matters: capacity/holdTime bounds AGGREGATE throughput through the
// throttled path regardless of how many concurrent connections an attacker
// throws at it — the number that matters for wall-clock brute-force cost.
//
// Deliberately BLOCKS (does not skip) once full: a request that can't get a
// slot immediately waits for one, up to bootstrapSecretMaxQueueWait — the
// earlier version of this fix skipped the delay under saturation, which
// reopened exactly the concurrency bypass above. See bootstrapSecretThrottle
// for why the wait itself is ALSO bounded (VULN-905/906: an even earlier
// version of this comment claimed WriteTimeout bounded an unbounded wait —
// it doesn't, for a handler blocked in a channel receive that hasn't
// attempted any I/O yet).
//
// Sized at 64: capacity/holdTime ≈ 64/3s ≈ 21 req/s absolute ceiling through
// the throttled path under sustained attack, however many connections the
// attacker opens — generous enough for realistic simultaneous legitimate
// bootstrap-login bursts (this only gates requests once bn is already
// elevated, i.e. concurrent with actual failure noise, not routine traffic).
var bootstrapSecretDelaySemaphore = make(chan struct{}, 64)

// bootstrapSecretQueueAdmission bounds how many callers may be WAITING for a
// bootstrapSecretDelaySemaphore slot at once, independent of how many are
// currently holding one (VULN-906). Without this, an attacker opening more
// concurrent connections than bootstrapSecretDelaySemaphore's capacity would
// still pile up an unbounded number of goroutines/open sockets queued behind
// it — the semaphore caps THROUGHPUT past the gate, but nothing capped the
// SIZE of the queue in front of it. Sized well above the semaphore's own
// capacity so it only engages under genuinely extreme concurrency, past which
// a caller proceeds unthrottled rather than adding to an ever-growing queue.
var bootstrapSecretQueueAdmission = make(chan struct{}, 512)

// bootstrapSecretMaxQueueWait caps how long any single caller — attacker or
// legitimate operator alike — waits for a bootstrapSecretDelaySemaphore slot
// before giving up and proceeding unthrottled (VULN-905). Without this, a
// caller presenting the CORRECT secret during a sustained attack could be
// queued behind however many attacker-held/attacker-queued slots preceded it,
// with no bound but the admin server's own connection lifetime — denying the
// legitimate admin's access is exactly the harm this fix's own non-blocking
// telemetry (VULN-802) was designed to avoid elsewhere in this same handler;
// the same principle applies here. Matches the ladder's own max delay: a
// caller that has already effectively "waited its turn" for one full delay
// cycle gets to proceed rather than risk queuing indefinitely under a
// sustained flood.
const bootstrapSecretMaxQueueWait = 3 * time.Second

// bootstrapSecretDelay returns the artificial response delay to apply to a
// {"secret": ...} attempt, given the current cross-IP attempt count (bn, the
// value IncrRate just returned) in the active bootstrapSecretBruteforceWindow.
//
// This is the actual slowdown VULN-802 was missing: the telemetry counter
// alone only made a distributed guesser VISIBLE, never SLOWER. A hard block
// on this shared/global key was rejected (see the observe-only comment at the
// call site — it becomes an unauthenticated denial-of-service on every admin).
// A ramping delay is the middle ground: it costs a legitimate caller at most a
// few seconds of latency (and only when recent global attempt volume is
// already elevated — ordinary traffic never sees it), while multiplying a
// sustained/distributed guesser's wall-clock cost by orders of magnitude
// without ever refusing a correct secret.
//
// Applied unconditionally BEFORE the secret is compared, using only state
// that exists prior to this attempt's own outcome — so, like the telemetry
// counter it rides on, it cannot become a timing side-channel on whether THIS
// attempt's secret is correct: two requests presenting the same bn always
// wait the same amount, whichever cool one holds the real secret.
//
// Capped at 3s: long enough to matter to an automated guesser making many
// requests, short enough to bound each individual held request. That alone
// does NOT bound TOTAL concurrent holds, though: a distributed attacker with
// many source IPs could otherwise open enough simultaneous connections to
// turn the delay itself into a socket/goroutine amplification vector, right
// when bn is highest (VULN-904-A) — bootstrapSecretDelaySemaphore at the call
// site bounds that.
func bootstrapSecretDelay(bn int64) time.Duration {
	switch {
	case bn > bootstrapSecretBruteforceLimit*3/4: // > 30: near/at the alert threshold (41)
		return 3 * time.Second
	case bn > bootstrapSecretBruteforceLimit/2: // > 20
		return 1 * time.Second
	case bn > bootstrapSecretBruteforceLimit/4: // > 10
		return 200 * time.Millisecond
	default:
		return 0
	}
}

// bootstrapSecretRealSleep applies d, or returns early if ctx is cancelled
// first (the client disconnected — no point holding the goroutine for the
// rest of the delay). Kept as a standalone named function — not inlined into
// the bootstrapSecretSleep var below — specifically so a test can call it
// directly and exercise the real timer/cancellation logic even after
// TestMain has replaced the var with a no-op stub for everything else
// (VULN-904-B: an earlier version of this test called through the var,
// which TestMain had already stubbed by the time the test ran, so it always
// passed regardless of whether cancellation actually worked).
func bootstrapSecretRealSleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// bootstrapSecretSleep applies the delay ladder; defaults to
// bootstrapSecretRealSleep. A package-level var so tests can replace it with
// a no-op and exercise the counting/threshold logic in milliseconds instead
// of the real multi-second ladder.
var bootstrapSecretSleep = bootstrapSecretRealSleep

// bootstrapSecretThrottle waits for a bootstrapSecretDelaySemaphore slot and
// applies delay via bootstrapSecretSleep, or gives up — proceeding
// unthrottled rather than denying anything — if ctx is cancelled, the
// admission queue is already saturated, or the wait exceeds
// bootstrapSecretMaxQueueWait. Returns whether the throttle actually ran
// (true) so the caller can decide whether to count it.
//
// delay <= 0 is a no-op (not throttled), never touching either channel —
// callers are expected to have already checked bootstrapSecretDelay(bn) > 0,
// but this stays safe to call unconditionally either way.
//
// Every give-up path here is a deliberate choice, all with the same shape as
// the original decision to make the cross-IP counter observe-only rather
// than blocking (VULN-802's call site comment): under genuinely extreme
// concurrency, this throttle chooses to let MORE guesses through unthrottled
// over denying a possibly-legitimate caller — the aggregate-throughput bound
// this mechanism exists for (VULN-904-A) only needs to hold under realistic
// attack volumes, not literally every volume up to infinity, and giving up
// gracefully beats an operator's correct secret timing out mid-incident
// (VULN-905/CHAIN-905 — a review found the very first blocking version of
// this function had no cap on wait time at all, so a sustained flood could
// queue a legitimate login behind it for as long as the admin server's own
// connection lifetime, which is a denial in practice, not a delay).
//
// Extracted from the {"secret": ...} login path specifically so this is
// independently testable without a full HTTP round trip.
func bootstrapSecretThrottle(ctx context.Context, delay time.Duration) (throttled bool) {
	if delay <= 0 {
		return false
	}

	// Admission cap (VULN-906): bound how many callers may be waiting at
	// once, independent of how many are holding a slot — without this, an
	// attacker opening enough concurrent connections still piles up an
	// unbounded number of goroutines/sockets queued in the select below.
	select {
	case bootstrapSecretQueueAdmission <- struct{}{}:
	default:
		return false
	}
	defer func() { <-bootstrapSecretQueueAdmission }()

	timer := time.NewTimer(bootstrapSecretMaxQueueWait)
	defer timer.Stop()
	select {
	case bootstrapSecretDelaySemaphore <- struct{}{}:
		// Deferred, not a bare receive (VULN-907): if bootstrapSecretSleep
		// ever panicked between acquire and release, a bare `<-sem` would
		// never run and this slot would be lost for the life of the
		// process — capacity silently rotting toward zero across repeated
		// panics. A slot acquired here is always released, panic or not.
		func() {
			defer func() { <-bootstrapSecretDelaySemaphore }()
			bootstrapSecretSleep(ctx, delay)
		}()
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

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
		// AdminBootstrapSecretDisabled must close this path exactly like it
		// closes the Bearer-header path in middleware/admin.go: an operator
		// who flips it (e.g. after suspecting AEGIS_ADMIN_SECRET leaked)
		// believes the credential is dead everywhere. Checked BEFORE the
		// compare — same "closed regardless of correctness" shape as the
		// middleware gate — so this doesn't even leak a timing signal about
		// whether a presented secret would otherwise have matched.
		if h.cfg.AdminBootstrapSecretDisabled {
			fail("secret", "")
			return
		}
		// Cross-IP brute-force TELEMETRY for the bootstrap secret (VULN-802),
		// deliberately observe-only, not blocking. Email/password's accountLoginKey
		// can safely BLOCK on its shared key because it's scoped to one account —
		// worst case an attacker locks out that one user. AEGIS_ADMIN_SECRET has no
		// such scoping: it is ONE secret for the whole deployment, so a blocking
		// gate on a key shared by definition would let any unauthenticated caller
		// lock every admin out of the bootstrap path with a handful of requests —
		// trading the distributed-brute-force gap for a trivial, unauthenticated
		// denial-of-service. Instead this counts failures across all IPs and fires
		// one alert per window when the same threshold the account gate uses is
		// crossed, giving ops the cross-IP visibility the per-IP gate above cannot
		// provide — plus, since VULN-904, an actual slowdown for a sustained/
		// distributed guesser (see bootstrapSecretDelay) — without ever
		// refusing a legitimate, correct secret.
		bootstrapTelemetryOK := true
		var bn int64
		var berr error
		if bn, berr = h.store.IncrRate(r.Context(), bootstrapSecretLoginKey, bootstrapSecretBruteforceWindow); berr != nil {
			bootstrapTelemetryOK = false
			h.log.Error("login: bootstrap-secret brute-force telemetry unavailable", map[string]any{"error": berr.Error()})
		} else if bn == int64(bootstrapSecretBruteforceLimit)+1 {
			// Fire once per window at the threshold crossing, not on every
			// subsequent failure, so a sustained attack doesn't spam the log at
			// the same volume it's attacking at.
			h.log.Warn("admin_bootstrap_secret_bruteforce_suspected", map[string]any{
				"ip": ip, "failures_in_window": bn, "window": bootstrapSecretBruteforceWindow.String(),
			})
			h.store.IncrMetric(r.Context(), "admin_bootstrap_secret_bruteforce_suspected")
		}
		// VULN-904 fix: ramp in a response delay ahead of the alert threshold.
		// bn is 0 when the store call above errored (bootstrapTelemetryOK ==
		// false) — bootstrapSecretDelay(0) is 0, so a Redis outage fails this
		// throttle open too, consistent with every other gate in this handler.
		if bootstrapSecretThrottle(r.Context(), bootstrapSecretDelay(bn)) {
			h.store.IncrMetric(r.Context(), "admin_bootstrap_secret_throttled")
		}
		if subtle.ConstantTimeCompare([]byte(req.Secret), []byte(h.cfg.AdminSecret)) != 1 {
			fail("secret", "")
			return
		}
		// Credentials checked out: refund the telemetry slot too (VULN-901 fix),
		// so this counter tracks FAILURES only — matching its name and its
		// doc comment — instead of also counting every legitimate CI/operator
		// bootstrap login, which would otherwise make the alert fire on normal
		// traffic and train operators to ignore it. Mirrors the per-IP/
		// per-account gates' own DecrRate-on-success below.
		if bootstrapTelemetryOK {
			h.store.DecrRate(r.Context(), bootstrapSecretLoginKey)
		}
		// Loud, unconditional log on every successful use — mirrors
		// middleware/admin.go's Bearer-path log, so this always-super-admin,
		// per-operator-unauditable credential's usage is equally visible to
		// log-based alerting regardless of which entry point presented it.
		h.log.Warn("admin_bootstrap_secret_used", map[string]any{
			"path": r.URL.Path, "method": r.Method, "ip": ip,
		})
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
