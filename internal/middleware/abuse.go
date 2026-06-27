package middleware

import (
	"net/http"
	"strconv"
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
	sensitivity := cfg.Sensitivity
	if sensitivity <= 0 {
		sensitivity = 3.0
	}
	adaptiveMin := cfg.AdaptiveMinObjects
	if adaptiveMin <= 0 {
		adaptiveMin = 8
	}
	// The baseline must outlive a single window so it reflects the consumer's norm
	// across windows, not just the current one.
	baselineTTL := 24 * window

	// Build the false-positive allowlist once. A consumer named here is exempt
	// from all abuse detection (A6 FP control).
	allow := make(map[string]bool, len(cfg.Allowlist))
	for _, c := range cfg.Allowlist {
		if c = strings.TrimSpace(c); c != "" {
			allow[c] = true
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)
			subject := r.Header.Get("X-Gateway-Subject")
			consumer := subject
			if consumer == "" {
				consumer = "ip:" + ip
			}

			// Allowlisted consumers skip detection entirely — they are known-benign
			// high-cardinality callers (batch jobs, indexers, internal admins).
			if allow[consumer] {
				next.ServeHTTP(w, r)
				return
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
				// BFLA is a clear authorization violation on verified JWT roles —
				// high confidence, hence "critical". The explanation makes the alert
				// self-describing (A6 explainability).
				extra := map[string]any{
					"consumer":       consumer,
					"required_roles": pr.RequiredRoles,
					"severity":       "critical",
					"why": "consumer '" + consumer + "' called privileged path '" + pr.Path +
						"' holding none of the required roles " + strings.Join(pr.RequiredRoles, ","),
				}
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
				if maxCount > 0 {
					// EnumThreshold is the absolute hard ceiling (always enforced).
					overCeiling := int(maxCount) > threshold
					flagged := overCeiling
					why := "consumer '" + consumer + "' accessed " + strconv.FormatInt(maxCount, 10) +
						" distinct object IDs on '" + endpoint + "' (hard ceiling " + strconv.Itoa(threshold) + ")"

					// A2: per-consumer adaptive baseline. Compare this window against the
					// consumer's own learned norm; learn unless it is already a clear
					// hard-ceiling breach (so an attack does not poison the baseline).
					var baseline float64
					if cfg.Adaptive {
						b, err := st.TrackBaseline(r.Context(), consumer, endpoint, maxCount, !overCeiling, baselineTTL)
						if err != nil {
							log.Error("abuse: baseline tracking failed", map[string]any{"error": err.Error()})
						} else {
							baseline = b
							if !flagged && int(maxCount) >= adaptiveMin && float64(maxCount) > b*sensitivity {
								flagged = true
								why = "consumer '" + consumer + "' accessed " + strconv.FormatInt(maxCount, 10) +
									" distinct object IDs on '" + endpoint + "' — " +
									strconv.FormatFloat(float64(maxCount)/maxF(b, 1), 'f', 1, 64) +
									"x its baseline of " + strconv.FormatFloat(b, 'f', 1, 64) +
									" (sensitivity " + strconv.FormatFloat(sensitivity, 'f', 1, 64) + ")"
							}
						}
					}

					if flagged {
						// BOLA is heuristic (legitimate pagination/bulk reads can resemble
						// enumeration), so it is "warning", not "critical". The explanation
						// states observed vs allowed/baseline so an operator can judge it
						// or allowlist the consumer.
						extra := map[string]any{
							"consumer":         consumer,
							"distinct_objects": maxCount,
							"endpoint":         endpoint,
							"severity":         "warning",
							"why":              why,
						}
						if cfg.Adaptive {
							extra["baseline"] = baseline
						}
						if cfg.BlockMode {
							SecurityDeny(w, r, log, st, "bola_enumeration", ip, http.StatusTooManyRequests, extra)
							return
						}
						recordAbuse(r, log, st, "bola_enumeration", ip, extra)
					}
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

// maxF returns the larger of two floats (used to avoid divide-by-zero when
// formatting the baseline multiple).
func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
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
