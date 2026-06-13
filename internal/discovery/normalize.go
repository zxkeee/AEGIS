// Package discovery implements passive API discovery and posture management:
// it builds a catalog of the company's real API endpoints from live traffic,
// classifies how well each endpoint is protected, tracks who consumes it, and
// powers the reporting/dashboard layer.
package discovery

import (
	"regexp"
	"strings"
)

// Dynamic path-segment detectors. A segment matching any of these is collapsed
// to the "{id}" placeholder so that /users/42 and /users/99 map to the same
// endpoint template /users/{id}. This both gives a stable catalog key and caps
// cardinality (an attacker flooding random paths cannot create endless entries).
var (
	reAllDigits = regexp.MustCompile(`^\d+$`)
	reUUID      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reLongHex   = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reHasDigit  = regexp.MustCompile(`\d`)
	// Long opaque tokens (base64url / random IDs): mostly alphanumerics, long,
	// and containing at least one digit (to avoid collapsing real path words).
	reOpaque = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
)

const placeholder = "{id}"

// NormalizePath converts a concrete request path into a stable endpoint template
// by replacing dynamic segments with "{id}". It is deterministic and allocation
// -light so it can run on the hot request path.
func NormalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}

	// Preserve a single trailing slash distinction is not useful for cataloging;
	// strip it so /users/ and /users collapse together (except root).
	trimmed := strings.TrimRight(p, "/")
	if trimmed == "" {
		return "/"
	}

	segs := strings.Split(trimmed, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		if isDynamicSegment(s) {
			segs[i] = placeholder
		}
	}
	out := strings.Join(segs, "/")
	if out == "" {
		return "/"
	}
	return out
}

// isDynamicSegment reports whether a single path segment looks like a variable
// identifier rather than a fixed resource name.
func isDynamicSegment(s string) bool {
	switch {
	case reAllDigits.MatchString(s):
		return true
	case reUUID.MatchString(s):
		return true
	case reLongHex.MatchString(s):
		return true
	case reOpaque.MatchString(s) && reHasDigit.MatchString(s):
		return true
	}
	return false
}

// EndpointKey builds the canonical "METHOD /path/template" key used as the
// catalog identity for an endpoint.
func EndpointKey(method, path string) string {
	return strings.ToUpper(method) + " " + NormalizePath(path)
}
