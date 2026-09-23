// Package safefetch holds the outbound-fetch policy for destinations an
// operator configured and the gateway pinned to https.
//
// It is a leaf package for the same reason internal/tenant is: the policy is
// needed by internal/middleware (threat feed, JWKS) and by internal/alert
// (webhook delivery), and middleware already imports alert. Leaving the policy
// in middleware would have meant either an import cycle or a second copy — and
// the last time this policy existed in only one of the places that needed it,
// the place without it was the one authenticating production traffic.
//
// # Why the check is on the resolved address
//
// The first version of this package inspected the URL's host STRING. That
// cannot work, and an audit demonstrated it: every one of these passed the
// check and then connected to loopback anyway —
//
//	https://localhost./jwks      the trailing dot loses the EqualFold match
//	https://2130706433/jwks      127.0.0.1 in decimal
//	https://127.1/jwks           the short form
//	https://0x7f.0.0.1/jwks      hexadecimal
//
// — because the string is not what the dialer connects to. The resolver is, and
// it accepts forms net.ParseIP rejects. The same hole covers any DNS name with
// a private A record, which needs no trickery at all: anyone can obtain a
// genuine certificate for a domain that resolves to 127.0.0.1, so pinning https
// buys nothing against it.
//
// So the decision now happens in net.Dialer.Control, which runs after
// resolution with the address the connection will actually use. That closes the
// numeric forms, the trailing dot, DNS names and DNS rebinding in one place,
// and it protects the FIRST request as well as redirects — the host an operator
// typed was never checked at all before.
package safefetch

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// maxHops caps redirect chains. Five is generous for a webhook or a JWKS
// document and short enough that a redirect loop fails fast.
const maxHops = 5

// Client returns an http.Client that refuses to connect to an internal address
// and follows only https redirects, whatever the URL says.
//
// what names the caller in errors, so an operator reading a log knows which
// fetch refused. timeout applies to the whole request.
//
// Use this instead of building an http.Client with Redirect as CheckRedirect:
// the redirect policy alone leaves the initial address unchecked, and that is
// the address an operator's own configuration supplies.
func Client(what string, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	d.Control = func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%s: cannot parse dial address %q: %w", what, address, err)
		}
		ip := net.ParseIP(host)
		// Control always receives a literal address, so a nil here means the
		// resolver handed us something unexpected. Refuse rather than guess.
		if ip == nil {
			return fmt.Errorf("%s: refusing to dial unparseable address %q", what, host)
		}
		if IsPrivateOrLocalIP(ip) {
			return fmt.Errorf("%s: refusing to connect to internal address %s "+
				"(the name resolved there)", what, ip)
		}
		return nil
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: d.DialContext, ForceAttemptHTTP2: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return Redirect(what, req, via)
		},
	}
}

// InternalClient returns a client for a destination that is SUPPOSED to be on
// the operator's own network, and is therefore allowed to reach a private
// address that Client refuses.
//
// It exists because the blanket rule is wrong for one class of destination. A
// webhook is a public endpoint and a private address there means something has
// gone wrong; a SIEM is the opposite — Splunk and Elasticsearch live on 10.0/8
// in essentially every deployment that has them, and refusing to reach one is
// refusing to integrate at all.
//
// What stays refused, because none of it is ever a SIEM:
//
//   - loopback — the gateway's own admin API listens there, so a "collector"
//     on 127.0.0.1 is the gateway posting its alerts to itself;
//   - link-local — 169.254.169.254 is cloud metadata, the single most valuable
//     SSRF target there is, and metadata.google.internal resolves to it;
//   - unspecified and multicast — not destinations.
//
// This is a narrower relaxation than it may look: the operator still cannot
// point a sink at the metadata service, and the decision still happens on the
// RESOLVED address, so a public hostname with a private A record is judged by
// where it actually goes. What it does allow is the ordinary case, and the
// operator has to ask for it per sink.
func InternalClient(what string, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	d.Control = func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%s: cannot parse dial address %q: %w", what, address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("%s: refusing to dial unparseable address %q", what, host)
		}
		if IsNeverADestination(ip) {
			return fmt.Errorf("%s: refusing to connect to %s — loopback, link-local "+
				"and multicast are never a collector, whatever the config says", what, ip)
		}
		return nil
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: d.DialContext, ForceAttemptHTTP2: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return Redirect(what, req, via)
		},
	}
}

// IsNeverADestination reports whether a RESOLVED address is one no configured
// destination may be, even one deliberately marked as internal.
//
// Deliberately NOT a subset relationship with IsPrivateOrLocalIP that anyone
// has to reason about: this is its own list, and private unicast is absent from
// it on purpose.
func IsNeverADestination(ip net.IP) bool {
	if ip == nil {
		return true // unknown is not safe
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

// Redirect is the scheme-and-hop half of the policy, as an
// http.Client.CheckRedirect.
//
// It no longer inspects the host: that is the dialer's job now, because a host
// string does not determine where a connection goes. What it still does is
// refuse a downgrade off https and cap the chain — neither of which the dialer
// can see.
//
// Config validation pins the URL an operator wrote; without this, a redirect
// from that host silently unpins it to http://. Enforcing the scheme at config
// time and then letting the client follow anything is a guarantee that only
// holds until the first 302.
func Redirect(what string, req *http.Request, via []*http.Request) error {
	if len(via) >= maxHops {
		return fmt.Errorf("%s: too many redirects", what)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%s: refusing non-https redirect to %q", what, req.URL.Redacted())
	}
	return nil
}

// IsPrivateOrLocalIP reports whether a RESOLVED address is one no
// operator-configured destination should ever be: loopback, private,
// link-local (which covers 169.254.169.254 cloud metadata), unspecified,
// multicast, or an IPv4-mapped IPv6 form of any of those.
//
// It takes a net.IP rather than a string on purpose. The string form is what
// the previous version checked, and strings are where localhost., 127.1 and
// 2130706433 hide.
func IsPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return true // unknown is not safe
	}
	// ::ffff:127.0.0.1 and friends: reduce to the v4 address before deciding,
	// or the loopback test misses them.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

// IsPrivateOrLocalHostname is a cheap pre-filter for a host that is already an
// IP literal or an obvious local name. It is NOT the control — the dialer is —
// and it exists so an obviously-internal destination is rejected at config time
// with a clear message instead of at the first request.
//
// It deliberately treats a trailing dot as the same name: "localhost." is the
// fully-qualified form and resolves identically.
func IsPrivateOrLocalHostname(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return IsPrivateOrLocalIP(ip)
	}
	return false
}

// CheckDestination validates an operator-supplied URL at configuration time.
//
// Resolution happens here, so a name pointing at an internal address is
// rejected when it is configured rather than on the first fetch. It is a
// convenience, not the control: DNS can change afterwards, which is why the
// dialer checks again on every connection.
func CheckDestination(ctx context.Context, what, rawURL string) error {
	host := rawURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return fmt.Errorf("%s: no host in %q", what, rawURL)
	}
	if IsPrivateOrLocalHostname(host) {
		return fmt.Errorf("%s: %q is an internal address", what, host)
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		// Unresolvable at config time is not fatal: the name may exist later,
		// and the dialer will check again. Refusing here would make a transient
		// DNS failure a startup failure.
		return nil
	}
	for _, ip := range ips {
		if IsPrivateOrLocalIP(ip) {
			return fmt.Errorf("%s: %q resolves to the internal address %s", what, host, ip)
		}
	}
	return nil
}
