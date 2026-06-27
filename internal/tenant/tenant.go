// Package tenant carries the resolved tenant identity on a request context.
// It is a leaf package (imports only the standard library) so every layer —
// middleware, discovery, store, forensic, api — can read the tenant without an
// import cycle. See docs/design/multitenancy.md (ADR-001).
package tenant

import "context"

// Default is the implicit tenant used when multi-tenancy is disabled and for
// backfilling pre-existing single-tenant data. It must equal
// config.DefaultTenant.
const Default = "default"

type ctxKey struct{}

// With returns a copy of ctx carrying the given tenant id.
func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// From returns the tenant resolved for this context, or Default if none was set.
// Storage layers use this to scope every read and write.
func From(ctx context.Context) string {
	if t, ok := ctx.Value(ctxKey{}).(string); ok && t != "" {
		return t
	}
	return Default
}
