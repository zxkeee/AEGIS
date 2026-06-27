package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"

	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"
)

// idShape limits tenant/user identifiers to characters that are safe to embed
// in URLs and Redis keys (no colons, no slashes). Enforced on every create.
var idShape = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// requireSuperAdmin gates endpoints that can affect more than one tenant.
// AdminAuth has already ensured the caller is authenticated; this is the
// additional cross-tenant gate.
func (h *handlers) requireSuperAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireMutator(w, r) {
		return false
	}
	if !iam.IsSuperAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "super-admin role required")
		return false
	}
	return true
}

// canManageTenant reports whether the caller is allowed to read/modify the
// given tenant's user list. Super-admins can manage any tenant; ordinary admins
// can manage only their own.
func (h *handlers) canManageTenant(r *http.Request, target string) bool {
	if iam.IsSuperAdmin(r.Context()) {
		return true
	}
	return tenant.From(r.Context()) == target
}

// usersAvailable rejects the request when no iam store is wired (i.e. the
// gateway started without forensic_dsn).
func (h *handlers) usersAvailable(w http.ResponseWriter) bool {
	if h.users == nil {
		writeError(w, http.StatusServiceUnavailable, "user management requires forensic_dsn / iam store")
		return false
	}
	return true
}

// ── Tenants ─────────────────────────────────────────────────────────────────

// GET /api/tenants — list all tenants. Super-admin only.
func (h *handlers) listTenants(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	if !iam.IsSuperAdmin(r.Context()) {
		// Non-super-admins only see their own tenant — surfacing the full list
		// would leak the names of other organisations on the deployment.
		writeJSON(w, http.StatusOK, map[string]any{
			"tenants": []map[string]string{{"id": tenant.From(r.Context())}},
			"count":   1,
		})
		return
	}
	if !h.usersAvailable(w) {
		return
	}
	ts, err := h.users.ListTenants(r.Context())
	if err != nil {
		h.log.Error("admin: list tenants failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "could not list tenants")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": ts, "count": len(ts)})
}

// POST /api/tenants {"id": "...", "name": "..."} — super-admin only.
func (h *handlers) createTenant(w http.ResponseWriter, r *http.Request) {
	if !h.requireSuperAdmin(w, r) {
		return
	}
	if !h.usersAvailable(w) {
		return
	}
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if !idShape.MatchString(req.ID) {
		writeError(w, http.StatusBadRequest, "tenant id must match [a-zA-Z0-9_-]{1,64}")
		return
	}
	if req.Name == "" {
		req.Name = req.ID
	}
	if err := h.users.CreateTenant(r.Context(), req.ID, req.Name); err != nil {
		h.log.Error("admin: create tenant failed", map[string]any{"error": err.Error(), "id": req.ID})
		writeError(w, http.StatusInternalServerError, "could not create tenant")
		return
	}
	h.log.Info("admin: tenant created", map[string]any{"id": req.ID})
	writeJSON(w, http.StatusCreated, map[string]any{"id": req.ID, "name": req.Name})
}

// DELETE /api/tenants/{id} — super-admin only. Idempotent: 200 even when the
// tenant did not exist, so a UI can issue the call freely.
func (h *handlers) deleteTenant(w http.ResponseWriter, r *http.Request) {
	if !h.requireSuperAdmin(w, r) {
		return
	}
	if !h.usersAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if id == "" || id == tenant.Default {
		writeError(w, http.StatusBadRequest, "cannot delete the default tenant")
		return
	}
	existed, err := h.users.DeleteTenant(r.Context(), id)
	if err != nil {
		h.log.Error("admin: delete tenant failed", map[string]any{"error": err.Error(), "id": id})
		writeError(w, http.StatusInternalServerError, "could not delete tenant")
		return
	}
	h.log.Info("admin: tenant deleted", map[string]any{"id": id, "existed": existed})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": existed})
}

// ── Users ───────────────────────────────────────────────────────────────────

// GET /api/users — list users in the caller's tenant (or, for super-admins,
// the tenant given as ?tenant=...; empty = all tenants).
func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	if !h.usersAvailable(w) {
		return
	}
	target := r.URL.Query().Get("tenant")
	if !iam.IsSuperAdmin(r.Context()) {
		// Ordinary admins are pinned to their own tenant regardless of what
		// they ask for; ignore the query param silently to avoid info leaks.
		target = tenant.From(r.Context())
	}
	us, err := h.users.ListUsers(r.Context(), target)
	if err != nil {
		h.log.Error("admin: list users failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": us, "count": len(us)})
}

// POST /api/users {"email","password","role","tenant","super_admin"}
//
// RBAC: super-admin can create users in any tenant and may set super_admin=true.
// An ordinary admin may only create users in their own tenant and may not grant
// super-admin. Viewers cannot create users.
func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	if !h.requireMutator(w, r) {
		return
	}
	if !h.usersAvailable(w) {
		return
	}
	var req struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		Role       string `json:"role"`
		Tenant     string `json:"tenant"`
		SuperAdmin bool   `json:"super_admin"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if len(req.Password) < 12 {
		writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}
	role := iam.Role(req.Role)
	if role != iam.RoleAdmin && role != iam.RoleViewer {
		role = iam.RoleAdmin // sensible default
	}
	target := strings.TrimSpace(req.Tenant)
	if target == "" {
		target = tenant.From(r.Context())
	}
	if !h.canManageTenant(r, target) {
		writeError(w, http.StatusForbidden, "cannot create users in another tenant")
		return
	}
	if req.SuperAdmin && !iam.IsSuperAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "only super-admins can grant super-admin")
		return
	}

	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate user id")
		return
	}
	u := iam.User{
		ID:         "u-" + hex.EncodeToString(idBytes),
		TenantID:   target,
		Email:      req.Email,
		Role:       role,
		SuperAdmin: req.SuperAdmin,
	}
	if err := h.users.CreateUser(r.Context(), u, req.Password); err != nil {
		// Most likely cause is a duplicate email per tenant; surfacing the raw
		// driver error would leak schema details, so we genericise it.
		h.log.Error("admin: create user failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusConflict, "could not create user (does the email already exist?)")
		return
	}
	h.log.Info("admin: user created",
		map[string]any{"id": u.ID, "tenant": u.TenantID, "role": string(u.Role), "super": u.SuperAdmin})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          u.ID,
		"tenant":      u.TenantID,
		"email":       u.Email,
		"role":        string(u.Role),
		"super_admin": u.SuperAdmin,
	})
}

// DELETE /api/users/{id} — admin in the user's tenant or any super-admin.
// Refuses to delete the caller's own account (avoid locking yourself out).
func (h *handlers) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !h.requireMutator(w, r) {
		return
	}
	if !h.usersAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "user id required")
		return
	}
	// Refuse to delete your own account — avoids an operator locking themselves
	// out. The bearer/bootstrap session has no UserID, so this never blocks it.
	if uid := iam.UserID(r.Context()); uid != "" && uid == id {
		writeError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	// Cheapest tenant-scope check: list the caller's allowed tenants and refuse
	// IDs we cannot find. Super-admins always pass.
	allTenants := iam.IsSuperAdmin(r.Context())
	scope := tenant.From(r.Context())
	if !allTenants {
		us, err := h.users.ListUsers(r.Context(), scope)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not verify scope")
			return
		}
		found := false
		for _, u := range us {
			if u.ID == id {
				found = true
				break
			}
		}
		if !found {
			// Return 403 rather than 404 so we don't leak whether the id exists
			// in another tenant.
			writeError(w, http.StatusForbidden, "cannot delete users in another tenant")
			return
		}
	}
	deleted, err := h.users.DeleteUser(r.Context(), id)
	if err != nil {
		h.log.Error("admin: delete user failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "could not delete user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": deleted})
}
