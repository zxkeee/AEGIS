package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/secevent"
	"api-gateway/internal/tenant"
)

const defaultSchemaMaxBody = 1 << 20 // 1 MiB

// SchemaValidation enforces a positive-security model: a request is validated
// against its documented OpenAPI/Swagger operation, and a non-conforming request
// is flagged (monitor) or rejected with 422 (block). This catches what a
// signature WAF cannot — mass assignment (undocumented body fields), type
// confusion, missing required parameters — by allowing only what the contract
// permits. See docs/design/schema-enforcement.md.
//
// The contract is resolved per request via specFor: a per-tenant uploaded
// spec (PUT /api/discovery/spec) takes precedence over the config-level spec
// (discovery.spec_path) when a catalog is wired, so a tenant's own uploaded
// contract is actually enforced and not just fed to the drift report
// (audit finding, 2026-08-22). Without a catalog, specFor is a fixed closure
// returning the config-level spec, matching the pre-fix behavior. An
// undocumented operation is not enforced (fail-open): unknown endpoints are
// the drift/findings layer's concern, not this one.
func SchemaValidation(cfg config.SchemaConfig, specFor func(context.Context) *discovery.Spec, log Logger, st DenySink) Middleware {
	if !cfg.Enabled || specFor == nil {
		return passthrough
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultSchemaMaxBody
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			spec := specFor(r.Context())
			if spec == nil {
				next.ServeHTTP(w, r) // no spec for this tenant (or none configured): not enforced
				return
			}
			template := discovery.NormalizePath(r.URL.Path)
			op := spec.LookupOp(r.Method, template)
			if op == nil {
				next.ServeHTTP(w, r) // undocumented operation: not enforced
				return
			}

			// Buffer the body (bounded) only when the operation documents one, then
			// restore it for the proxy. A body over the cap cannot be validated
			// without risking OOM: in BlockMode this is a fail-closed reject (an
			// attacker cannot defeat positive-security enforcement by padding the
			// body past the cap); in monitor mode it passes through but is still
			// recorded, so operators can see the enforcement-coverage gap.
			var body []byte
			if r.Body != nil && op.Body != nil {
				buf, tooBig, rest := readBounded(r.Body, maxBody)
				if tooBig {
					ip := RealIP(r)
					extra := map[string]any{"template": template, "max_body_bytes": maxBody}

					if cfg.BlockMode {
						log.BlockEvent("schema_skipped_oversized", ip, r.URL.Path, r.Method, extra)
						st.IncrMetric(r.Context(), "schema_skipped_oversized")
						st.PushForensic(r.Context(), secevent.Entry{
							Tenant: tenant.From(r.Context()), Timestamp: time.Now().UTC(),
							IP: ip, Path: r.URL.Path, Method: r.Method,
							Reason: "schema_skipped_oversized", Code: http.StatusRequestEntityTooLarge, Extra: extra,
						})
						http.Error(w, "request body exceeds schema validation limit", http.StatusRequestEntityTooLarge)
						return
					}

					log.BlockEvent("schema_skipped_oversized_monitor", ip, r.URL.Path, r.Method, extra)
					st.IncrMetric(r.Context(), "schema_skipped_oversized")
					st.PushForensic(r.Context(), secevent.Entry{
						Tenant: tenant.From(r.Context()), Timestamp: time.Now().UTC(),
						IP: ip, Path: r.URL.Path, Method: r.Method,
						Reason: "schema_skipped_oversized_monitor", Code: http.StatusOK, Extra: extra,
					})
					r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), rest))
					next.ServeHTTP(w, r)
					return
				}
				body = buf
				r.Body = io.NopCloser(bytes.NewReader(buf))
			}

			violations := op.ValidateRequest(r.URL.Query(), body)
			if len(violations) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ip := RealIP(r)
			extra := map[string]any{
				"template":   template,
				"violations": violationStrings(violations),
			}

			if !cfg.BlockMode {
				// Monitor: record the violation but let the request through, so an
				// operator can tune the contract before enforcing.
				log.BlockEvent("schema_violation_monitor", ip, r.URL.Path, r.Method, extra)
				st.IncrMetric(r.Context(), "schema_violation")
				st.PushForensic(r.Context(), secevent.Entry{
					Tenant: tenant.From(r.Context()), Timestamp: time.Now().UTC(),
					IP: ip, Path: r.URL.Path, Method: r.Method,
					Reason: "schema_violation_monitor", Code: http.StatusOK, Extra: extra,
				})
				next.ServeHTTP(w, r)
				return
			}

			// Block: reject with a machine-readable 422.
			log.BlockEvent("schema_violation", ip, r.URL.Path, r.Method, extra)
			st.IncrMetric(r.Context(), "blocked_schema_violation")
			st.PushForensic(r.Context(), secevent.Entry{
				Tenant: tenant.From(r.Context()), Timestamp: time.Now().UTC(),
				IP: ip, Path: r.URL.Path, Method: r.Method,
				Reason: "schema_violation", Code: http.StatusUnprocessableEntity, Extra: extra,
			})
			writeSchemaError(w, violations)
		})
	}
}

// readBounded reads up to max bytes. When the body exceeds max it returns the
// bytes read so far plus a reader for the remainder, so the caller can splice
// the body back together and pass it through unvalidated.
func readBounded(rc io.Reader, max int64) (buf []byte, tooBig bool, rest io.Reader) {
	buf, _ = io.ReadAll(io.LimitReader(rc, max+1))
	if int64(len(buf)) > max {
		return buf, true, rc
	}
	return buf, false, nil
}

func violationStrings(vs []discovery.Violation) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.String()
	}
	return out
}

func writeSchemaError(w http.ResponseWriter, vs []discovery.Violation) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":      "request does not conform to the API schema",
		"violations": vs,
	})
}
