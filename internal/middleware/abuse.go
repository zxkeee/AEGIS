package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/gql"
	"api-gateway/internal/secevent"
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
//
// graphQLPath, when set, is the same path configured for the Discovery
// middleware (security.api_inventory.graphql_path) — one setting shared by
// both, so an operator doesn't declare "where GraphQL lives" twice. A POST to
// this path has its body parsed as a GraphQL operation (internal/gql), and
// id-shaped arguments on its top-level fields (e.g. `id: 42` in
// `user(id: 42) { ... }`) become BOLA candidates the same way a path segment,
// query parameter, or JSON body field already do — see ROADMAP.md B5. Empty
// (default) disables this: zero behavior change for a gateway that doesn't
// front GraphQL.
func AbuseDetection(cfg config.AbuseConfig, graphQLPath string, log Logger, st abuseStore) Middleware {
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

	// Response-body owner fields (confirmed ownership). Cleaned once.
	ownerFields := make([]string, 0, len(cfg.OwnerFields))
	for _, f := range cfg.OwnerFields {
		if f = strings.TrimSpace(f); f != "" {
			ownerFields = append(ownerFields, f)
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
			// Match case-insensitively and on a segment boundary: a backend that
			// routes case-insensitively would otherwise let "/ADMIN" slip past a
			// "/admin" rule, and a raw prefix would falsely flag "/administrators".
			lpath := strings.ToLower(r.URL.Path)
			for _, pr := range cfg.Privileged {
				if pr.Path == "" || !config.PathHasPrefix(lpath, strings.ToLower(pr.Path)) {
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
			// endpoint (method-specific) drives enumeration; scope (method-
			// independent) drives ownership so a read-learned owner also protects
			// against a cross-owner write. Candidates cover both path-embedded IDs
			// (/orders/{id}) and query-string IDs (?order_id={id}): the latter used
			// to be a complete blind spot, since the value never appears in the path
			// template extractObjectIDs looks at.
			candidates := bolaTargets(r.Method, r.URL.Path, r.URL.Query(), bodyObjectIDs(r), peekGraphQLOperation(r, graphQLPath))

			blocked := false
			for _, cand := range candidates {
				if len(cand.ids) == 0 {
					continue
				}
				var maxCount int64
				for _, id := range cand.ids {
					cnt, err := st.TrackObjectAccess(r.Context(), consumer, cand.endpoint, id, window)
					if err != nil {
						log.Error("abuse: object-access tracking failed", map[string]any{"error": err.Error()})
						continue
					}
					if cnt > maxCount {
						maxCount = cnt
					}
				}
				if maxCount == 0 {
					continue
				}
				// EnumThreshold is the absolute hard ceiling (always enforced).
				overCeiling := int(maxCount) > threshold
				flagged := overCeiling
				why := "consumer '" + consumer + "' accessed " + strconv.FormatInt(maxCount, 10) +
					" distinct object IDs on '" + cand.endpoint + "' (hard ceiling " + strconv.Itoa(threshold) + ")"

				// A2: per-consumer adaptive baseline. Compare this window against the
				// consumer's own learned norm; learn unless it is already a clear
				// hard-ceiling breach (so an attack does not poison the baseline).
				var baseline float64
				if cfg.Adaptive {
					b, err := st.TrackBaseline(r.Context(), consumer, cand.endpoint, maxCount, !overCeiling, baselineTTL)
					if err != nil {
						log.Error("abuse: baseline tracking failed", map[string]any{"error": err.Error()})
					} else {
						baseline = b
						if !flagged && int(maxCount) >= adaptiveMin && float64(maxCount) > b*sensitivity {
							flagged = true
							why = "consumer '" + consumer + "' accessed " + strconv.FormatInt(maxCount, 10) +
								" distinct object IDs on '" + cand.endpoint + "' — " +
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
						"endpoint":         cand.endpoint,
						"severity":         "warning",
						"why":              why,
					}
					if cfg.Adaptive {
						extra["baseline"] = baseline
					}
					if cfg.BlockMode {
						SecurityDeny(w, r, log, st, "bola_enumeration", ip, http.StatusTooManyRequests, extra)
						blocked = true
						break
					}
					recordAbuse(r, log, st, "bola_enumeration", ip, extra)
				}
			}
			if blocked {
				return
			}

			// ── BOLA (object ownership): single-object IDOR ────────────────────
			// The enumeration check above needs MANY IDs to fire; this catches the
			// one-object case: a consumer reading a single object it does not own.
			// Only authenticated subjects qualify (an "ip:" identity is too unstable
			// under NAT/DHCP to attribute ownership); consumers holding a bypass role
			// (support/admin) are allowed to see others' objects.
			bypassed := len(cfg.OwnershipBypassRoles) > 0 && hasAnyRole(roles, cfg.OwnershipBypassRoles)
			anyIDs := false
			for _, cand := range candidates {
				if len(cand.ids) > 0 {
					anyIDs = true
					break
				}
			}
			if (cfg.ObjectOwnership || cfg.ObjectOwnershipBlock) && subject != "" && anyIDs && !bypassed {
				ownTTL := cfg.ObjectOwnershipTTL
				if ownTTL <= 0 {
					ownTTL = 168 * time.Hour
				}
				// The identity compared against the object's owner. Prefer the
				// propagated ownership claim (X-Gateway-Identity, set by JWT auth from
				// auth.identity_claim) so ownership works when the resource owner is not
				// the JWT subject; fall back to the subject when no claim is configured.
				identity := r.Header.Get("X-Gateway-Identity")
				if identity == "" {
					identity = subject
				}

				// Proactive block (before forwarding): if an object's confirmed owner
				// is already known and is someone else, deny the leak up front.
				if cfg.ObjectOwnershipBlock {
					for _, cand := range candidates {
						for _, id := range cand.ids {
							owner, known, err := st.GetObjectOwner(r.Context(), cand.scope, id)
							if err != nil {
								log.Error("abuse: object-owner lookup failed", map[string]any{
									"error": err.Error(), "fail_closed": cfg.OwnershipFailClosed,
								})
								// ObjectOwnershipBlock is the one BOLA control that actually
								// blocks traffic — the rest only detect-and-record. Default
								// is fail-open (skip this candidate, keep checking the rest)
								// to preserve availability; OwnershipFailClosed denies
								// instead, so a Redis outage during an active IDOR sweep
								// cannot silently disable the one control that blocks it.
								if cfg.OwnershipFailClosed {
									SecurityDeny(w, r, log, st, "bola_owner_store_unavailable", ip, http.StatusServiceUnavailable, map[string]any{
										"consumer": consumer, "object_id": id, "endpoint": cand.endpoint,
									})
									return
								}
								continue
							}
							if known && owner != "" && owner != identity {
								SecurityDeny(w, r, log, st, "bola_owner_block", ip, http.StatusForbidden, map[string]any{
									"consumer":  consumer,
									"object_id": id,
									"endpoint":  cand.endpoint,
									"owner":     owner,
									"severity":  "critical",
									"why": "consumer '" + consumer + "' denied " + r.Method + " on object '" + id + "' (" + cand.scope +
										") owned by '" + owner + "' — cross-owner access (BOLA) blocked before forwarding",
								})
								return
							}
						}
					}
				}

				if !cfg.ObjectOwnership {
					next.ServeHTTP(w, r)
					return
				}

				// Post-response: confirm ownership from the body (if OwnerFields is
				// configured) or fall back to the first-accessor heuristic. Evaluated
				// after the response so a 2xx confirms the object was actually returned
				// (a 4xx means the backend enforced authorization — not a leak).
				cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
				next.ServeHTTP(cw, r)
				if cw.status < 200 || cw.status >= 300 {
					return
				}

				var bodyOwner string
				if len(ownerFields) > 0 {
					bodyOwner = extractOwner(cw.buf, ownerFields)
				}

				if bodyOwner != "" {
					// CONFIRMED path: the response body names the object's owner. Bind
					// it (so future cross-owner requests are blocked) and, if it is not
					// the caller, flag a confirmed IDOR — a real data leak, "critical".
					// Bound against every candidate's last ID, since a request can carry
					// both a path ID and a query ID at once.
					for _, cand := range candidates {
						if len(cand.ids) == 0 {
							continue
						}
						objID := cand.ids[len(cand.ids)-1]
						if err := st.SetObjectOwner(r.Context(), cand.scope, objID, bodyOwner, ownTTL); err != nil {
							log.Error("abuse: set object-owner failed", map[string]any{"error": err.Error()})
						}
						if bodyOwner != identity {
							recordAbuse(r, log, st, "bola_object_ownership", ip, map[string]any{
								"consumer":  consumer,
								"object_id": objID,
								"endpoint":  cand.endpoint,
								"owner":     bodyOwner,
								"confirmed": true,
								"severity":  "critical",
								"why": "consumer '" + consumer + "' " + r.Method + " object '" + objID + "' (" + cand.scope +
									") owned by '" + bodyOwner + "' (from response body) — confirmed IDOR (BOLA)",
							})
						}
					}
					return
				}

				// HEURISTIC fallback: first-accessor ownership affinity.
				shared := cfg.SharedObjectThreshold
				if shared <= 0 {
					shared = 2
				}
				for _, cand := range candidates {
					for _, id := range cand.ids {
						prior, already, err := st.TrackObjectOwner(r.Context(), cand.scope, id, consumer, ownTTL)
						if err != nil {
							log.Error("abuse: object-owner tracking failed", map[string]any{"error": err.Error()})
							continue
						}
						if !already && prior >= 1 && int(prior) <= shared {
							recordAbuse(r, log, st, "bola_object_ownership", ip, map[string]any{
								"consumer":     consumer,
								"object_id":    id,
								"endpoint":     cand.endpoint,
								"prior_owners": prior,
								"severity":     "warning",
								"why": "consumer '" + consumer + "' " + r.Method + " object '" + id + "' (" + cand.scope +
									") owned by " + strconv.FormatInt(prior, 10) +
									" other consumer(s) and never accessed by it — possible IDOR (BOLA, heuristic)",
							})
						}
					}
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ownerBodyCap bounds how much of a JSON response body is buffered for owner
// extraction, so a large payload cannot blow up memory on the hot path.
const ownerBodyCap = 64 * 1024

// captureWriter tees the response through unchanged while copying up to
// ownerBodyCap bytes of a JSON body for owner extraction. It never delays or
// rewrites the response; non-JSON bodies are not buffered. Flush (SSE) and
// Hijack (WebSocket) reach the real connection via Unwrap.
type captureWriter struct {
	http.ResponseWriter
	status  int
	buf     []byte
	capture int // 0 = undecided, 1 = capturing JSON, -1 = skip
}

func (c *captureWriter) WriteHeader(code int) {
	c.status = code
	c.decide()
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) decide() {
	if c.capture != 0 {
		return
	}
	if isJSONContentType(c.Header().Get("Content-Type")) {
		c.capture = 1
	} else {
		c.capture = -1
	}
}

// jsonContentTypeRE mirrors waf.go's JSON-body detection (id:10000/10013/10014
// directives): Coraza treats any "application/...+json" suffix — not just the
// exact "application/json" — as a JSON body (application/vnd.api+json,
// application/merge-patch+json, application/hal+json, application/problem+json
// are all common, legitimate REST content types). bodyObjectIDs and
// captureWriter.decide originally only matched the bare "application/json"
// media type, so a request/response using one of those +json variants was
// fully parsed as JSON by the WAF but completely invisible to BOLA body-ID
// extraction and confirmed-owner binding — a sibling instance of the same
// "fix applied to some JSON-detection sites, not others" gap already closed
// on waf.go's own rules.
var jsonContentTypeRE = regexp.MustCompile(`(?i)^application/(?:[a-z0-9.+-]+\+)?json$`)

// isJSONContentType reports whether a Content-Type header value (parameters,
// e.g. "; charset=utf-8", stripped) denotes a JSON body.
func isJSONContentType(ct string) bool {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return jsonContentTypeRE.MatchString(strings.TrimSpace(ct))
}

func (c *captureWriter) Write(b []byte) (int, error) {
	c.decide()
	if c.capture == 1 && len(c.buf) < ownerBodyCap {
		room := ownerBodyCap - len(c.buf)
		if room > len(b) {
			room = len(b)
		}
		c.buf = append(c.buf, b[:room]...)
	}
	return c.ResponseWriter.Write(b)
}

func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// extractOwner parses a JSON body and returns the value of the first matching
// owner field, checked at the top level and under a "data" wrapper (a common API
// envelope). Numbers keep exact precision (json.Number), so integer IDs compare
// cleanly against the subject.
func extractOwner(body []byte, fields []string) string {
	if len(body) == 0 {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return ""
	}
	if v := ownerFromMap(m, fields); v != "" {
		return v
	}
	if d, ok := m["data"].(map[string]any); ok {
		return ownerFromMap(d, fields)
	}
	return ""
}

func ownerFromMap(m map[string]any, fields []string) string {
	for _, f := range fields {
		if v, ok := m[f]; ok {
			switch t := v.(type) {
			case string:
				return t
			case json.Number:
				return t.String()
			case bool:
				return strconv.FormatBool(t)
			}
		}
	}
	return ""
}

// recordAbuse logs an abuse event and persists it to forensics WITHOUT denying
// the request (detect-only mode). Mirrors SecurityDeny's side effects minus the
// HTTP error, so detected-but-allowed events still appear in the console.
func recordAbuse(r *http.Request, log Logger, st DenySink, reason, ip string, extra map[string]any) {
	log.BlockEvent(reason, ip, r.URL.Path, r.Method, extra)
	st.IncrMetric(r.Context(), "abuse_"+reason)
	st.PushForensic(r.Context(), secevent.Entry{
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

// bolaCandidate is one BOLA detection target within a request: the
// method-specific endpoint key (used for enumeration), the method-independent
// object scope (used for ownership), and the concrete object ID(s) found.
type bolaCandidate struct {
	endpoint string
	scope    string
	ids      []string
}

// bolaTargets resolves ALL BOLA detection targets for a request: the
// path-embedded object (as before) plus any query-string parameter whose
// single value looks like an object identifier.
//
// The path target's object scope omits the method on purpose: order 1001 is
// the same object whether it is read (GET), modified (PUT/PATCH) or deleted
// (DELETE), so ownership learned from a read must also protect it against a
// cross-owner write.
//
// Path primary case: the normalized template already has "{id}" segments
// (numeric, UUID, hash, opaque) — those are the object IDs.
//
// Path fallback: when no segment normalizes to "{id}" (e.g. string slugs like
// /api/members/alice), the terminal segment of a collection is treated as the
// object ID under a synthesized "parent/{id}" template. Without this,
// enumerating string identifiers evades BOLA entirely, since each value would
// otherwise look like a distinct static endpoint.
//
// Query-string case (VULN-M02 fix): a REST endpoint that keys object access
// off a query parameter (?order_id=1002, ?user=42) rather than a path segment
// used to be a complete blind spot — the value never appears in the path
// template extractObjectIDs looks at, so it was never tracked, never counted
// toward the enumeration threshold, and never protected by ownership checks.
// Each qualifying parameter gets its own endpoint/scope keyed by parameter
// name, so distinct parameters never share one enumeration counter and a
// path-target and a query-target on the same request are tracked
// independently. A parameter's values are split on comma AND every repeated
// occurrence is inspected individually (?id=1&id=2&... and ?ids=1,2,3 both
// track each qualifying value) — the original fix only accepted a single
// scalar value and silently dropped the whole parameter otherwise, which let
// an attacker batch an entire enumeration sweep into one request and evade
// counting entirely while the identical sweep split across N requests would
// have been caught.
//
// Body case: an endpoint that keys object access off a JSON body field
// (PATCH /orders {"order_id":1002}, or a batch body {"ids":[1,2,3,...]}) was
// a complete blind spot too — bodyObjectIDs (called by the middleware before
// this) extracts id-shaped values from top-level/"data"-wrapped fields whose
// name looks like an object reference, and each field is tracked as its own
// endpoint/scope the same way a query parameter is.
//
// False positives across all targets are bounded by enum_threshold (default
// 50), the per-consumer adaptive baseline, and the allowlist.
func bolaTargets(method, rawPath string, query url.Values, bodyIDs map[string][]string, gqlOp *gql.Operation) []bolaCandidate {
	var out []bolaCandidate

	tmpl := discovery.NormalizePath(rawPath)
	if got := extractObjectIDs(rawPath, tmpl); len(got) > 0 {
		out = append(out, bolaCandidate{endpoint: method + " " + tmpl, scope: tmpl, ids: got})
	} else {
		segs := strings.Split(strings.Trim(rawPath, "/"), "/")
		if len(segs) >= 2 {
			last := segs[len(segs)-1]
			if last != "" {
				parent := discovery.NormalizePath("/" + strings.Join(segs[:len(segs)-1], "/"))
				if parent == "/" {
					parent = ""
				}
				scope := parent + "/{id}"
				out = append(out, bolaCandidate{endpoint: method + " " + scope, scope: scope, ids: []string{last}})
			}
		}
	}

	for name, vals := range query {
		var ids []string
		for _, v := range vals {
			for _, part := range strings.Split(v, ",") {
				if part = strings.TrimSpace(part); looksLikeObjectID(part) {
					ids = append(ids, part)
				}
			}
		}
		if len(ids) == 0 {
			continue
		}
		qScope := tmpl + "?" + name + "={id}"
		out = append(out, bolaCandidate{endpoint: method + " " + qScope, scope: qScope, ids: ids})
	}

	for name, ids := range bodyIDs {
		if len(ids) == 0 {
			continue
		}
		bScope := tmpl + ":body." + name
		out = append(out, bolaCandidate{endpoint: method + " " + bScope, scope: bScope, ids: ids})
	}

	// GraphQL case (ROADMAP.md B5): the URL path is always the same
	// "/graphql"-shaped tmpl no matter which operation ran, so the object-ID
	// key has to come from the operation itself, not the path. Scoped by
	// operation (CatalogKey: "query.GetUser") AND field name, not just field
	// name alone — two unrelated operations that both happen to have a field
	// called "user" must not share one enumeration counter or one owner
	// binding just because the argument name coincides.
	if gqlOp != nil {
		opKey := gqlOp.CatalogKey()
		for _, f := range gqlOp.TopFields {
			var ids []string
			for argName, val := range f.Args {
				if !looksLikeIDField(argName) {
					continue
				}
				ids = append(ids, idShapedValues(val)...)
			}
			if len(ids) == 0 {
				continue
			}
			gScope := tmpl + ":gql." + opKey + "." + f.Name
			out = append(out, bolaCandidate{endpoint: method + " " + gScope, scope: gScope, ids: ids})
		}
	}

	return out
}

// peekGraphQLOperation parses r's body as a GraphQL operation when r targets
// graphQLPath, restoring the body afterward either way (the proxy still
// needs the exact original bytes). Returns nil — not an error, silently —
// for anything that isn't a clean single-operation GraphQL request: wrong
// path/method, no body, oversized body, or a parse failure. BOLA detection is
// best-effort on top of passive parsing; a miss here must fall back to
// "no GraphQL candidates this request," never block or alter it.
func peekGraphQLOperation(r *http.Request, graphQLPath string) *gql.Operation {
	if graphQLPath == "" || r.URL.Path != graphQLPath || r.Method != http.MethodPost || r.Body == nil {
		return nil
	}
	buf, tooBig, rest := readBounded(r.Body, bodyIDCap)
	if tooBig {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), rest))
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))

	op, err := gql.Parse(buf)
	if err != nil {
		return nil
	}
	return op
}

// bodyIDCap bounds how much of a JSON request body is buffered for BOLA
// object-ID extraction — same DoS-safety rationale as ownerBodyCap.
const bodyIDCap = 64 * 1024

// bodyObjectIDs peeks up to bodyIDCap bytes of a JSON request body and
// returns, per field name, the id-shaped values of every top-level (or
// "data"-wrapped) field whose name looks like an object reference ("id", or
// ending in "_id"/"Id"). The body is rewound afterward (head + untouched
// remainder) so WAF/DLP/the proxy still see the complete, unconsumed stream —
// mirrors waf.go's screenXXE peek-and-rewind pattern. Returns nil for
// non-JSON, empty, or unparsable bodies.
func bodyObjectIDs(r *http.Request) map[string][]string {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return nil
	}

	head := make([]byte, bodyIDCap)
	n, _ := io.ReadFull(r.Body, head)
	head = head[:n]
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	if n == 0 {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(head))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil
	}

	out := make(map[string][]string)
	collectIDFields(m, out)
	if d, ok := m["data"].(map[string]any); ok {
		collectIDFields(d, out)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectIDFields scans a decoded JSON object's top-level fields for an
// id-shaped key (an exact "id", or a name ending "_id"/"Id" — e.g. order_id,
// userId) and appends every id-shaped value found under it (a scalar, or
// each qualifying element of an array — covering a batch body like
// {"ids":[1,2,3]}) into out, keyed by field name.
func collectIDFields(m map[string]any, out map[string][]string) {
	for k, v := range m {
		if !looksLikeIDField(k) {
			continue
		}
		out[k] = append(out[k], idShapedValues(v)...)
	}
}

// looksLikeIDField reports whether a JSON field name looks like an object
// reference: exactly "id"/"ids" (any case), or ending in "_id"/"_ids" or the
// camelCase "Id"/"Ids" suffix (orderId, userIds) — the plural form covers a
// batch-ID body ({"ids":[1,2,3]}). Deliberately narrower than a bare
// HasSuffix(k, "id") check, which would also match ordinary words like
// "valid" or "paid" — false positives are still bounded further by
// idShapedValues only accepting numeric/UUID-shaped values.
func looksLikeIDField(k string) bool {
	lk := strings.ToLower(k)
	if lk == "id" || lk == "ids" {
		return true
	}
	if strings.HasSuffix(k, "Id") || strings.HasSuffix(k, "ID") ||
		strings.HasSuffix(k, "Ids") || strings.HasSuffix(k, "IDs") {
		return true
	}
	return strings.HasSuffix(lk, "_id") || strings.HasSuffix(lk, "_ids")
}

// idShapedValues returns the id-shaped values found in v: the value itself
// if it is a qualifying scalar (string or JSON number), or the qualifying
// elements of v if it is an array (batch-ID bodies like {"ids":[1,2,3]}).
func idShapedValues(v any) []string {
	switch t := v.(type) {
	case string:
		if looksLikeObjectID(t) {
			return []string{t}
		}
	case json.Number:
		if s := t.String(); looksLikeObjectID(s) {
			return []string{s}
		}
	case int64:
		// GraphQL integer arguments (internal/gql, via ast.Value.Value) come
		// through as plain int64, not json.Number — bodyObjectIDs's source
		// (encoding/json with UseNumber) never produces this type, so this
		// case is GraphQL-only today, not dead code for the JSON path.
		if s := strconv.FormatInt(t, 10); looksLikeObjectID(s) {
			return []string{s}
		}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, idShapedValues(e)...)
		}
		return out
	}
	return nil
}

// objectIDNumericRE/objectIDUUIDRE bound looksLikeObjectID to values that are
// plausibly database/opaque identifiers, so a free-text search or filter
// query parameter (?q=..., ?name=...) is not mistaken for object enumeration.
var (
	objectIDNumericRE = regexp.MustCompile(`^[0-9]{1,32}$`)
	objectIDUUIDRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// looksLikeObjectID reports whether a query-parameter value is shaped like an
// object identifier (a decimal integer or a UUID) rather than free text.
func looksLikeObjectID(v string) bool {
	if v == "" {
		return false
	}
	return objectIDNumericRE.MatchString(v) || objectIDUUIDRE.MatchString(v)
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
