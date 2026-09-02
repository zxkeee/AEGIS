package middleware

import (
	"net/http"
	"strings"
	"unicode/utf8"
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
func PathSanity(log Logger, st DenySink) Middleware {
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
	//
	//    Path parameters are stripped before the comparison. A segment like
	//    "..;" — or "..;jsessionid=x" — is not literally "..", but every Java
	//    servlet container (Tomcat, Jetty, and Spring on top of them) strips the
	//    ";..." suffix during normalisation and then resolves what is left, so
	//    the backend sees "..". "/public/..;/orders" therefore matched an
	//    "auth.exclude: /public" prefix here and reached "/orders" there — the
	//    exact gateway-vs-backend disagreement this whole file exists to refuse,
	//    slipping through because the check compared the un-stripped segment
	//    (confirmed against a running gateway, 2026-09-02).
	for _, seg := range strings.Split(r.URL.Path, "/") {
		if i := strings.IndexByte(seg, ';'); i >= 0 {
			seg = seg[:i]
		}
		if seg == ".." {
			return "path-traversal (..) segment in path"
		}
	}
	// 3. A literal backslash is a separator on some backends; treat as traversal
	//    risk when combined with dots.
	if strings.Contains(r.URL.Path, "\\") {
		return "backslash in path"
	}
	// 4. Double encoding. r.URL.Path has already been percent-decoded once, so a
	//    percent-escape STILL present in it means the client encoded the encoding:
	//    "%252e%252e" arrives here as "%2e%2e". We see dots that are not dots and
	//    match our prefixes accordingly; a backend that decodes a second time —
	//    common behind a second proxy, or in any framework that decodes path
	//    variables itself — sees "..". Only the three path-significant escapes are
	//    rejected, so an ordinary literal '%' in a path (a product code, an
	//    encoded label) is unaffected.
	lpath := strings.ToLower(r.URL.Path)
	for _, enc := range []string{"%2e", "%2f", "%5c"} {
		if strings.Contains(lpath, enc) {
			return "double-encoded path escape (" + enc + ") in path"
		}
	}
	// 5. Invalid UTF-8. An overlong encoding such as %c0%af is not "/" to Go and
	//    not "/" to a modern backend, but it is to any decoder that accepts
	//    overlong forms — the classic IIS traversal. A normalised API path is
	//    valid UTF-8, so rejecting the rest costs nothing and removes a whole
	//    family of decoder-disagreement tricks rather than one spelling of it.
	if !utf8.ValidString(r.URL.Path) {
		return "invalid UTF-8 in path"
	}
	return ""
}
