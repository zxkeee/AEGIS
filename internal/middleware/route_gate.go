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
