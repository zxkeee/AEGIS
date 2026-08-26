package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/gql"
	"api-gateway/internal/tenant"
)

// graphQLBodyCap bounds how much of a candidate GraphQL request body
// Discovery buffers to parse. Mirrors gql.Parse's own cap (a body over this
// can't be a valid single operation worth attributing anyway) — kept as its
// own constant so this file doesn't need to know gql's internals, just that
// something bounded is required before buffering client-controlled bytes.
const graphQLBodyCap = 64 * 1024

// Catalog is the dependency the Discovery middleware records observations to.
// Implemented by *discovery.Catalog.
type Catalog interface {
	Record(obs discovery.Observation)
}

// obsKey is the private context key under which the per-request Observation
// accumulator pointer is stored. Inner middleware (JWT, DLP) enrich it; the
// Discovery middleware finalises and records it.
type obsKeyType struct{}

var obsKey = obsKeyType{}

// observationFrom returns the in-flight Observation accumulator, or nil.
func observationFrom(ctx context.Context) *discovery.Observation {
	o, _ := ctx.Value(obsKey).(*discovery.Observation)
	return o
}

// Discovery passively catalogs every API call that reaches the proxy. It seeds
// an Observation into the request context (so inner middleware can attach
// identity and PII signals), measures latency and status, and records the
// result to the catalog. It must sit inside the auth/DLP middleware so those can
// enrich the observation, and outside the proxy so it captures the final status.
func Discovery(cfg config.APIInventoryConfig, cat Catalog, log Logger) Middleware {
	if !cfg.Enabled || cat == nil {
		return passthrough
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if cfg.GraphQLPath != "" && path == cfg.GraphQLPath && r.Method == http.MethodPost && r.Body != nil {
				if opPath, ok := graphQLOperationPath(r, cfg.GraphQLPath); ok {
					path = opPath
				}
				// ok == false: not parseable as GraphQL (or over the size cap) —
				// r.Body has already been restored either way; fall back to the
				// plain configured path, same as if GraphQLPath were unset.
			}
			obs := &discovery.Observation{
				Tenant:     tenant.From(r.Context()),
				Method:     r.Method,
				Path:       path,
				ConsumerIP: RealIP(r),
			}
			ctx := context.WithValue(r.Context(), obsKey, obs)

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(sw, r.WithContext(ctx))

			// Endpoints that don't exist (404) are not part of the company's API
			// surface — skip them so probing can't pollute the catalog.
			if sw.status == http.StatusNotFound {
				return
			}

			obs.Status = sw.status
			obs.LatencyMs = time.Since(start).Milliseconds()
			cat.Record(*obs)

			log.Info("api_access", map[string]any{
				"method":     obs.Method,
				"path":       obs.Path,
				"status":     obs.Status,
				"latency_ms": obs.LatencyMs,
				"consumer":   consumerLabel(obs),
				"ip":         obs.ConsumerIP,
				"request_id": r.Header.Get("X-Request-ID"),
			})
		})
	}
}

// graphQLOperationPath peeks r.Body (bounded, then always restored — the
// proxy still needs the exact original bytes downstream) and, if it parses
// as a single GraphQL operation, returns a synthetic per-operation path such
// as "/graphql/query/GetUser" instead of the bare configured GraphQLPath.
// This is what turns "every GraphQL call is the same catalog entry" into
// "each operation is its own entry" — see ROADMAP.md B5. ok is false for
// anything that isn't cleanly parseable as one operation (not GraphQL at
// all, malformed, ambiguous multi-operation document, oversized body) —
// callers fall back to the plain path; a parse miss must never affect the
// proxied request itself.
func graphQLOperationPath(r *http.Request, basePath string) (path string, ok bool) {
	buf, tooBig, rest := readBounded(r.Body, graphQLBodyCap)
	if tooBig {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), rest))
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))

	op, err := gql.Parse(buf)
	if err != nil {
		return "", false
	}
	name := op.Name
	if name == "" {
		name = "anonymous"
	}
	return basePath + "/" + op.Type + "/" + name, true
}

// consumerLabel picks the strongest available consumer identity for logging.
func consumerLabel(obs *discovery.Observation) string {
	switch {
	case obs.ConsumerSubject != "":
		return "jwt:" + obs.ConsumerSubject
	case obs.ConsumerKey != "":
		return "key:" + obs.ConsumerKey
	default:
		return "ip:" + obs.ConsumerIP
	}
}
