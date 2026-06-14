package middleware

import (
	"net/http"
	"strings"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/store"
)

// AbuseDetection detects authorization abuse that signature WAFs miss:
//
//   - BFLA (Broken Function Level Authorization): a consumer calls a privileged
//     path without holding any of the roles that path requires.
//   - BOLA / IDOR (Broken Object Level Authorization): a single consumer accesses
//     an unusually large number of distinct object IDs on one endpoint within a
//     window — the classic enumeration / object-sweeping pattern.
//
// Detection is passive and identity-aware: it uses the verified subject and roles
// propagated by the JWT middleware, so it must run AFTER authentication. In the
// default detect-only mode it records events without disrupting traffic; in
// block mode it denies the offending request.
func AbuseDetection(cfg config.AbuseConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	window := cfg.Window
	if window <= 0 {
		window = time.Minute
	}
	threshold := cfg.EnumThreshold
	if threshold <= 0 {
		threshold = 50
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)
			subject := r.Header.Get("X-Gateway-Subject")
			consumer := subject
			if consumer == "" {
				consumer = "ip:" + ip
			}
			roles := splitRoles(r.Header.Get("X-Gateway-Roles"))

			// ── BFLA: privileged path without an allowed role ──────────────────
			for _, pr := range cfg.Privileged {
				if pr.Path == "" || !strings.HasPrefix(r.URL.Path, pr.Path) {
					continue
				}
				if hasAnyRole(roles, pr.RequiredRoles) {
					break // authorized for this prefix
				}
				extra := map[string]any{"consumer": consumer, "required_roles": pr.RequiredRoles}
				if cfg.BlockMode {
					SecurityDeny(w, r, log, st, "bfla_privileged_access", ip, http.StatusForbidden, extra)
					return
				}
				recordAbuse(r, log, st, "bfla_privileged_access", ip, extra)
				break
			}

			// ── BOLA: object-ID enumeration by one consumer ────────────────────
			tmpl := discovery.NormalizePath(r.URL.Path)
			ids := extractObjectIDs(r.URL.Path, tmpl)
			if len(ids) > 0 {
				endpoint := r.Method + " " + tmpl
				var maxCount int64
				for _, id := range ids {
					cnt, err := st.TrackObjectAccess(r.Context(), consumer, endpoint, id, window)
					if err != nil {
						log.Error("abuse: object-access tracking failed", map[string]any{"error": err.Error()})
						continue
					}
					if cnt > maxCount {
						maxCount = cnt
					}
				}
				if int(maxCount) > threshold {
					extra := map[string]any{"consumer": consumer, "distinct_objects": maxCount, "endpoint": endpoint}
					if cfg.BlockMode {
						SecurityDeny(w, r, log, st, "bola_enumeration", ip, http.StatusTooManyRequests, extra)
						return
					}
					recordAbuse(r, log, st, "bola_enumeration", ip, extra)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// recordAbuse logs an abuse event and persists it to forensics WITHOUT denying
// the request (detect-only mode). Mirrors SecurityDeny's side effects minus the
// HTTP error, so detected-but-allowed events still appear in the console.
func recordAbuse(r *http.Request, log Logger, st Store, reason, ip string, extra map[string]any) {
	log.BlockEvent(reason, ip, r.URL.Path, r.Method, extra)
	st.IncrMetric(r.Context(), "abuse_"+reason)
	st.PushForensic(r.Context(), store.ForensicEntry{
		Timestamp: time.Now().UTC(),
		IP:        ip,
		Path:      r.URL.Path,
		Method:    r.Method,
		Reason:    reason,
		Code:      http.StatusOK, // allowed (detect-only)
		Extra:     extra,
	})
}

// splitRoles parses the comma-separated X-Gateway-Roles header.
func splitRoles(h string) []string {
	if h == "" {
		return nil
	}
	parts := strings.Split(h, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// hasAnyRole reports whether the consumer holds at least one required role. An
// empty required set means the prefix is open (no specific role demanded).
func hasAnyRole(have, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, req := range required {
		for _, h := range have {
			if h == req {
				return true
			}
		}
	}
	return false
}

// extractObjectIDs returns the concrete values of the dynamic ("{id}") segments
// of a request path, by aligning the raw path with its normalized template.
func extractObjectIDs(rawPath, template string) []string {
	rawSegs := strings.Split(strings.Trim(rawPath, "/"), "/")
	tplSegs := strings.Split(strings.Trim(template, "/"), "/")
	if len(rawSegs) != len(tplSegs) {
		return nil
	}
	var ids []string
	for i, t := range tplSegs {
		if t == "{id}" && rawSegs[i] != "" {
			ids = append(ids, rawSegs[i])
		}
	}
	return ids
}
