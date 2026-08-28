package middleware

import "net/http"

// RouteGate enforces per-route control overrides in the data plane.
//
// The posture engine already computes the *effective* controls for a path
// (global security.* merged with per-route overrides). Historically only the
// posture/reporting layer consulted those overrides, so the dashboard could
// report an endpoint as "protected" via require_auth: true while the request
// actually reached the backend unauthenticated — the tool reported protection
// that did not exist. RouteGate closes that gap: the real control middleware is
// constructed once (force-enabled), and the gate decides per request whether it
// runs, based on the same effective-controls function the posture engine uses.
//
// enabled(path) reports whether the control applies to the request path. When
// true the wrapped control runs; when false the request passes straight through
// to next. Because both branches are wired at construction time, gating costs a
// single boolean check (plus the resolver lookup) per request.
func RouteGate(enabled func(path string) bool, inner Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		applied := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enabled(r.URL.Path) {
				applied.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RouteSwitch is RouteGate with a second branch: instead of "apply the control
// or pass straight through", it picks between two middlewares per request.
//
// It exists for auth. Gating JWT off entirely on routes that do not require it
// meant identity was never extracted there — so a caller that DID present a
// valid token was recorded as anonymous, because nothing had looked. That made
// the catalog's anon_count mean "we did not check" while the findings layer
// read it as "the caller had no credential", and reported PII on such a route
// as "N requests arrived without authentication" when in fact every one of them
// was authenticated (audit finding, 2026-08-28). Routes that do not require
// auth now run a soft, identify-only pass instead of nothing at all.
func RouteSwitch(cond func(path string) bool, whenTrue, whenFalse Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		yes := whenTrue(next)
		no := whenFalse(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cond(r.URL.Path) {
				yes.ServeHTTP(w, r)
				return
			}
			no.ServeHTTP(w, r)
		})
	}
}
