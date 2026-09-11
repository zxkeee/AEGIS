// Package safefetch holds the redirect policy for outbound fetches whose
// destination an operator configured and the gateway pinned to https.
//
// It is a leaf package for the same reason internal/tenant is: the policy is
// needed by internal/middleware (threat feed, JWKS) and by internal/alert
// (webhook delivery), and middleware already imports alert. Leaving the policy
// in middleware would have meant either an import cycle or a second copy — and
// the last time this policy existed in only one of the places that needed it,
// the place without it was the one authenticating production traffic.
package safefetch

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// maxHops caps redirect chains. Five is generous for a webhook or a JWKS
// document and short enough that a redirect loop fails fast.
const maxHops = 5

// Redirect is an http.Client.CheckRedirect policy: follow only https redirects
// to non-private hosts, and cap the hop count. what names the caller in the
// error, so an operator reading a log knows which fetch refused.
//
// Config validation pins the URL an operator wrote; without this, a redirect
// from that host silently unpins it — to http://, or to an internal address
// such as 169.254.169.254. Enforcing the scheme at config time and then letting
// the client follow anything is a guarantee that only holds until the first 302.
func Redirect(what string, req *http.Request, via []*http.Request) error {
	if len(via) >= maxHops {
		return fmt.Errorf("%s: too many redirects", what)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%s: refusing non-https redirect to %q", what, req.URL.Redacted())
	}
	if host := req.URL.Hostname(); IsPrivateOrLocalHost(host) {
		return fmt.Errorf("%s: refusing redirect to private/loopback host %q", what, host)
	}
	return nil
}

// IsPrivateOrLocalHost reports whether a redirect target host is an internal
// address a public destination must never point us at. It blocks the literal
// "localhost" and any IP literal that is loopback, private, link-local (covers
// 169.254.169.254 cloud metadata) or unspecified. A bare DNS name that resolves
// to a private IP is not caught here (no lookup on the hot path); the scheme +
// IP-literal checks cover the realistic MITM/SSRF vectors.
func IsPrivateOrLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a domain name; allowed (https + public-name redirect)
	}
	return ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
