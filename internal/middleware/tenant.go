package middleware

import (
	"context"
	"net"
	"net/http"
	"sort"
	"strings"

	"api-gateway/internal/config"
	"api-gateway/internal/tenant"
)

// TenantID returns the tenant resolved for this request, or the default tenant
// if none was set (e.g. multi-tenancy disabled). Thin wrapper over tenant.From
// so existing middleware callers keep working.
func TenantID(ctx context.Context) string { return tenant.From(ctx) }

// WithTenant returns a context carrying the given tenant (used by tests and by
// the resolver itself).
func WithTenant(ctx context.Context, t string) context.Context { return tenant.With(ctx, t) }

// tenantRoute pairs a route path prefix with its owning tenant, for
// longest-prefix matching (model B, authoritative).
type tenantRoute struct {
	path   string
	tenant string
}

// TenantResolve maps each incoming request to a tenant and stores it on the
// request context (ADR-001, model "B + A"):
//
//   - B (authoritative): the matched route's tenant_id.
//   - A (convenience):   the Host/SNI → tenant mapping.
//
// When both resolve and disagree, the request is rejected — never coerced. An
// unresolved tenant is rejected with 404 (no enumeration of which tenants
// exist). The client-supplied X-Tenant-* headers are always stripped so a
// caller can never assert its own tenant.
//
// With multi-tenancy disabled this is a near-passthrough that pins every request
// to config.DefaultTenant (legacy single-tenant behaviour).
func TenantResolve(cfg config.MultitenancyConfig, routes []config.RouteConfig, log Logger, st MetricsSink) Middleware {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				stripTenantHeaders(r)
				next.ServeHTTP(w, r.WithContext(WithTenant(r.Context(), config.DefaultTenant)))
			})
		}
	}

	// Host → tenant (model A).
	hostMap := make(map[string]string)
	for _, t := range cfg.Tenants {
		for _, h := range t.Hosts {
			hostMap[strings.ToLower(h)] = t.ID
		}
	}

	// A prefix claimed by more than one tenant cannot identify a tenant by
	// itself — that is the "one API surface, many customers" shape the proxy
	// registers host-scoped (see proxy.routePatterns). Such a prefix is left
	// OUT of the route table below so the Host decides it. Without this,
	// whichever route happened to sort first would win the model-B lookup and
	// the host/route agreement check would then 404 every tenant but that one,
	// making the feature the proxy now supports unreachable in the data plane.
	owner := make(map[string]string, len(routes))
	ambiguous := make(map[string]bool)
	for _, rt := range routes {
		p := routePrefix(rt.Path)
		if prev, seen := owner[p]; seen && prev != rt.TenantID {
			ambiguous[p] = true
			continue
		}
		owner[p] = rt.TenantID
	}

	// Route prefix → tenant (model B), longest prefix wins.
	troutes := make([]tenantRoute, 0, len(routes))
	for _, rt := range routes {
		p := routePrefix(rt.Path)
		if ambiguous[p] {
			continue
		}
		troutes = append(troutes, tenantRoute{path: p, tenant: rt.TenantID})
	}
	sort.Slice(troutes, func(i, j int) bool { return len(troutes[i].path) > len(troutes[j].path) })

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stripTenantHeaders(r)

			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			tenantHost := hostMap[strings.ToLower(host)]

			// Case-insensitive match, same as posture.go's matchRoute/authExcluded
			// and abuse.go's BFLA check: a backend that routes case-insensitively
			// would otherwise let a case-varied path ("/Orders" vs a configured
			// "/orders") dodge its longer, more specific route and fall through
			// to a shorter, case-differing-safe one — misattributing the request
			// to the WRONG TENANT'S Redis/catalog/metrics isolation, exactly the
			// "confused deputy" ADR-001 exists to prevent. (Security audit,
			// 2026-08-22: this file's own comment above once claimed this class
			// was "already fixed" here — it wasn't, for the case dimension.)
			lpath := strings.ToLower(r.URL.Path)
			var tenantRouteID string
			for _, tr := range troutes {
				// Segment-boundary match (not raw HasPrefix): route "/orders" must
				// own "/orders" and "/orders/42" but NOT "/ordersXYZ", otherwise an
				// adjacent path name is silently attributed to the wrong tenant —
				// corrupting that tenant's metrics/Redis/catalog isolation. An empty
				// prefix (a root "/" route) matches everything, as before.
				if tr.path == "" || config.PathHasPrefix(lpath, strings.ToLower(tr.path)) {
					tenantRouteID = tr.tenant
					break
				}
			}

			// Route is authoritative; host must agree when both are present.
			if tenantHost != "" && tenantRouteID != "" && tenantHost != tenantRouteID {
				log.Warn("tenant_resolve: host/route tenant mismatch", map[string]any{
					"host_tenant": tenantHost, "route_tenant": tenantRouteID, "path": r.URL.Path,
				})
				st.IncrMetric(r.Context(), "tenant_mismatch")
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			tenant := tenantRouteID
			if tenant == "" {
				tenant = tenantHost
			}
			if tenant == "" {
				st.IncrMetric(r.Context(), "tenant_unresolved")
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithTenant(r.Context(), tenant)))
		})
	}
}

// stripTenantHeaders removes any client-supplied X-Tenant-* header so a caller
// cannot assert its own tenant (same spoof-defence as CleanHeaders).
func stripTenantHeaders(r *http.Request) {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-tenant-") {
			r.Header.Del(name)
		}
	}
}

// routePrefix reduces a ServeMux route pattern to a plain path prefix for
// tenant matching. It drops any leading "METHOD " and trailing wildcard so
// "/orders/" and "/orders" both match "/orders/42".
func routePrefix(pattern string) string {
	p := pattern
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = p[i+1:] // strip "GET " style method prefix
	}
	if h := strings.IndexByte(p, '/'); h > 0 {
		p = p[h:] // strip "host/path" — keep from the first slash
	}
	return strings.TrimSuffix(p, "/")
}
