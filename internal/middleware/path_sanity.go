package middleware

import (
	"net/http"
	"strings"
)

// PathSanity rejects requests whose URL path uses traversal or encoded path
// separators, before any prefix-based security decision (auth.exclude, per-route
// gating, tenant routing) is made.
//
// Why this exists: those decisions match r.URL.Path against configured prefixes.
// A path like /public/..%2fsecret matches the excluded "/public" prefix, so auth
// is skipped — yet a backend that decodes %2f and resolves ".." serves /secret to
// an unauthenticated caller. The gateway and the backend disagree on the real
// target. Rather than try to canonicalise (and risk a different mismatch), we
// refuse the ambiguous request outright: in a normalised API path a ".." segment
// or an encoded separator has no legitimate use and is a classic policy-bypass
// vector. This must run early — ahead of auth, routing and the WAF.
func PathSanity(log Logger, st Store) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if reason := unsafePath(r); reason != "" {
				ip := RealIP(r)
				SecurityDeny(w, r, log, st, "path_traversal_blocked", ip, http.StatusBadRequest,
					map[string]any{"why": reason, "path": r.URL.EscapedPath()})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// unsafePath returns a non-empty reason when the request path must be rejected.
func unsafePath(r *http.Request) string {
	// 1. Encoded path separators hide segment boundaries from prefix matching.
	//    EscapedPath() preserves the on-the-wire encoding (RawPath).
	esc := strings.ToLower(r.URL.EscapedPath())
	if strings.Contains(esc, "%2f") || strings.Contains(esc, "%5c") {
		return "encoded path separator (%2f/%5c) in path"
	}
	// 2. A ".." segment in the decoded path is traversal. Checked per-segment so a
	//    literal filename like "..foo" or a dotfile "." is not falsely rejected.
	for _, seg := range strings.Split(r.URL.Path, "/") {
		if seg == ".." {
			return "path-traversal (..) segment in path"
		}
	}
	// 3. A literal backslash is a separator on some backends; treat as traversal
	//    risk when combined with dots.
	if strings.Contains(r.URL.Path, "\\") {
		return "backslash in path"
	}
	return ""
}
