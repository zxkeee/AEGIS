package middleware

import (
	"fmt"
	"net"
	"net/http"

	"api-gateway/internal/config"
)

// parseIPOrCIDRList parses a list of entries that may be bare IPs or CIDRs
// (mirroring InitTrustedProxies) into *net.IPNet. Bare IPs are normalised to
// /32 (IPv4) or /128 (IPv6) host routes. Invalid entries are reported via the
// returned error but do not stop parsing the rest of the list — config.Validate
// is responsible for rejecting bad entries before this ever runs at request time.
func parseIPOrCIDRList(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	var firstErr error
	for _, s := range entries {
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			s = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid IP/CIDR %q: %w", s, err)
			}
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets, firstErr
}

// matchesAnyNet reports whether ip falls inside any of nets.
func matchesAnyNet(nets []*net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IPGuard enforces IP whitelist/blacklist rules. Entries may be bare IPs or
// CIDR ranges (e.g. "10.0.0.0/8") — both are matched by containment, unlike a
// plain exact-string set, so an operator-configured subnet is actually honoured
// instead of silently never matching.
func IPGuard(cfg config.IPGuardConfig, log Logger, st ipGuardStore) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	// config.Validate is expected to have already rejected invalid entries;
	// parse errors here are logged but non-fatal so a single bad entry doesn't
	// disable the rest of the list at runtime.
	whitenets, err := parseIPOrCIDRList(cfg.Whitelist)
	if err != nil {
		log.Error("ip_guard: whitelist parse error", map[string]any{"error": err.Error()})
	}
	blacknets, err := parseIPOrCIDRList(cfg.Blacklist)
	if err != nil {
		log.Error("ip_guard: blacklist parse error", map[string]any{"error": err.Error()})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)

			// Always allow whitelisted IPs/subnets
			if matchesAnyNet(whitenets, ip) {
				next.ServeHTTP(w, r)
				return
			}

			// Check static blacklist (IPs/subnets)
			if matchesAnyNet(blacknets, ip) {
				SecurityDeny(w, r, log, st, "ip_blacklisted", ip, http.StatusForbidden, nil)
				return
			}

			// Check dynamic blacklist (Redis)
			blocked, err := st.IsIPBlocked(r.Context(), ip)
			if err != nil {
				log.Error("ip_guard: redis error", map[string]any{
					"error":       err.Error(),
					"fail_closed": cfg.FailClosed,
				})
				if cfg.FailClosed {
					// High-assurance mode: a backing-store outage must not silently
					// disable IP blocking, so deny rather than pass through.
					SecurityDeny(w, r, log, st, "ip_guard_store_unavailable", ip,
						http.StatusServiceUnavailable, nil)
					return
				}
				// Default: fail open to preserve availability.
			}
			if blocked {
				SecurityDeny(w, r, log, st, "ip_blocked_dynamic", ip, http.StatusForbidden, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
