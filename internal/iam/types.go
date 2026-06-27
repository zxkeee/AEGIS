// Package iam holds identity & access-management primitives for the admin
// console: roles, the resolved session that drives RBAC, and the user/tenant
// store. The types in this file are a leaf (stdlib only) so every layer —
// middleware, store, api — can use them without an import cycle.
package iam

import "context"

// Role gates which admin endpoints a session may invoke. We deliberately keep
// only two so the rules are obvious: admin can mutate, viewer can only read.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

// CanMutate reports whether this role is allowed to perform state-changing
// admin operations (block IP, revoke JWT, etc.).
func (r Role) CanMutate() bool { return r == RoleAdmin }

// Session is the authenticated console session stored server-side in Redis.
// Tenant + Role are propagated into request context by the AdminAuth middleware
// so every admin handler is automatically scoped.
type Session struct {
	CSRF     string `json:"csrf"`
	TenantID string `json:"tenant_id"`
	Role     Role   `json:"role"`
	// UserID is empty for the legacy bearer/secret bootstrap session — those
	// are super-admin with no per-user accountability. Real console logins fill
	// it so audit logs carry the operator.
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
	// SuperAdmin grants cross-tenant management (tenant CRUD, creating users
	// in any tenant). Distinct from Role: a SuperAdmin is always also Role=admin
	// in their home tenant, but the converse is not true.
	SuperAdmin bool `json:"super_admin,omitempty"`
}

type roleCtxKey struct{}
type superCtxKey struct{}
type userIDCtxKey struct{}

// WithUserID returns a copy of ctx carrying the authenticated operator's user
// ID. Empty for the legacy bearer/secret bootstrap session.
func WithUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, userIDCtxKey{}, id)
}

// UserID returns the authenticated operator's user ID, or "" if none (e.g. the
// bearer bootstrap session).
func UserID(ctx context.Context) string {
	v, _ := ctx.Value(userIDCtxKey{}).(string)
	return v
}

// WithRole returns a copy of ctx carrying the given role.
func WithRole(ctx context.Context, r Role) context.Context {
	return context.WithValue(ctx, roleCtxKey{}, r)
}

// FromContext returns the role on ctx. Absent role => RoleViewer (least
// privilege) so a forgotten WithRole never silently grants admin.
func FromContext(ctx context.Context) Role {
	if v, ok := ctx.Value(roleCtxKey{}).(Role); ok && v != "" {
		return v
	}
	return RoleViewer
}

// WithSuperAdmin marks the context as carrying cross-tenant management rights.
func WithSuperAdmin(ctx context.Context, super bool) context.Context {
	return context.WithValue(ctx, superCtxKey{}, super)
}

// IsSuperAdmin reports whether the context belongs to a super-admin. Default
// is false (least privilege).
func IsSuperAdmin(ctx context.Context) bool {
	v, _ := ctx.Value(superCtxKey{}).(bool)
	return v
}
