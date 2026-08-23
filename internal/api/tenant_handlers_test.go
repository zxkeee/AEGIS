package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/pgtest"
	"api-gateway/internal/store"
	"api-gateway/internal/tenant"

	"github.com/alicebob/miniredis/v2"
)

// pgDSN returns a schema-isolated integration-test DSN (or skips when unset).
// The dedicated "test_api" schema is created fresh per test, so this package's
// tables never collide with other packages under a parallel `go test ./...`.
// See internal/pgtest.
func pgDSN(t *testing.T) string {
	t.Helper()
	return pgtest.DSN(t, "test_api")
}

// freshHandlers wires a real iam.Store against the (freshly-created, empty)
// integration schema and returns a *handlers ready for direct method calls. No
// TRUNCATE is needed: pgtest.DSN gives each test a clean schema, and NewStore
// creates the tables empty inside it.
func freshHandlers(t *testing.T) *handlers {
	t.Helper()
	iamStore, err := iam.NewStore(pgDSN(t), logger.New("error"))
	if err != nil {
		t.Fatalf("iam.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = iamStore.Close() })

	// A real (miniredis-backed) Store, not nil: deleteTenant/deleteUser sweep
	// live sessions via h.store.RevokeSessions, matching production wiring
	// where Postgres (iam) and Redis (sessions) are always both present.
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	redisStore, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = redisStore.Close() })

	// AdminAuth disabled in tests so requireAuth passes without a cookie/bearer —
	// these tests exercise the RBAC policy layer (role + super-admin in ctx),
	// independent of cookie/CSRF mechanics covered by middleware tests.
	cfg := config.GatewayConfig{AdminAuth: false, AdminSecret: "test-secret-min-32-characters-1234"}
	return &handlers{
		store: redisStore,
		log:   logger.New("error"),
		cfg:   cfg,
		users: iamStore,
	}
}

// ctxAs returns a base context loaded with the tenant/role/super flags an
// AdminAuth handler would normally install.
func ctxAs(tnt string, role iam.Role, super bool) context.Context {
	ctx := tenant.With(context.Background(), tnt)
	ctx = iam.WithRole(ctx, role)
	return iam.WithSuperAdmin(ctx, super)
}

func doReq(h func(http.ResponseWriter, *http.Request), method, path string, ctx context.Context, body any) (*httptest.ResponseRecorder, map[string]any) {
	rec := httptest.NewRecorder()
	var buf []byte
	if body != nil {
		buf, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(buf))
	r.RemoteAddr = "1.2.3.4:1"
	r = r.WithContext(ctx)
	h(rec, r)
	var parsed map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	}
	return rec, parsed
}

// — Tenants —

func TestTenants_SuperAdminCanCRUD(t *testing.T) {
	h := freshHandlers(t)
	ctx := ctxAs("default", iam.RoleAdmin, true)

	// create
	rec, _ := doReq(h.createTenant, http.MethodPost, "/api/tenants", ctx,
		map[string]any{"id": "acme", "name": "ACME Corp"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("super-admin createTenant: %d, want 201", rec.Code)
	}

	// list (super-admin sees all)
	rec, body := doReq(h.listTenants, http.MethodGet, "/api/tenants", ctx, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("listTenants: %d", rec.Code)
	}
	if cnt, _ := body["count"].(float64); cnt != 1 {
		t.Fatalf("count = %v, want 1", body["count"])
	}
}

func TestTenants_AdminCannotCreate(t *testing.T) {
	h := freshHandlers(t)
	ctx := ctxAs("acme", iam.RoleAdmin, false)
	rec, _ := doReq(h.createTenant, http.MethodPost, "/api/tenants", ctx,
		map[string]any{"id": "globex"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ordinary admin createTenant: %d, want 403", rec.Code)
	}
}

func TestTenants_ViewerCannotMutate(t *testing.T) {
	h := freshHandlers(t)
	ctx := ctxAs("acme", iam.RoleViewer, false)
	rec, _ := doReq(h.createTenant, http.MethodPost, "/api/tenants", ctx,
		map[string]any{"id": "globex"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer createTenant: %d, want 403", rec.Code)
	}
}

func TestTenants_AdminListSeesOnlyOwn(t *testing.T) {
	h := freshHandlers(t)
	// Seed two tenants as super-admin.
	su := ctxAs("default", iam.RoleAdmin, true)
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "acme"})
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "globex"})

	// Ordinary admin from acme: must NOT learn that globex exists.
	rec, body := doReq(h.listTenants, http.MethodGet, "/api/tenants",
		ctxAs("acme", iam.RoleAdmin, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("listTenants: %d", rec.Code)
	}
	ts, _ := body["tenants"].([]any)
	if len(ts) != 1 {
		t.Fatalf("admin saw %d tenants; must see only own", len(ts))
	}
	first, _ := ts[0].(map[string]any)
	if first["id"] != "acme" {
		t.Fatalf("admin saw tenant %q, want only own", first["id"])
	}
}

func TestTenants_IDValidation(t *testing.T) {
	h := freshHandlers(t)
	ctx := ctxAs("default", iam.RoleAdmin, true)
	for _, badID := range []string{"", "with space", "with/slash", "with:colon"} {
		rec, _ := doReq(h.createTenant, http.MethodPost, "/api/tenants", ctx, map[string]any{"id": badID})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("bad id %q: got %d, want 400", badID, rec.Code)
		}
	}
}

func TestTenants_DeleteRevokesLiveSessions(t *testing.T) {
	h := freshHandlers(t)
	su := ctxAs("default", iam.RoleAdmin, true)
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "acme"})

	// Simulate a live console session for the deleted tenant, as CreateSession
	// would on login.
	sess := iam.Session{TenantID: "acme", UserID: "u1", Role: iam.RoleAdmin, CSRF: "csrf"}
	if err := h.store.CreateSession(context.Background(), "tok-acme", sess, time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	r := httptest.NewRequest(http.MethodDelete, "/api/tenants/acme", nil)
	r = r.WithContext(su)
	r.SetPathValue("id", "acme")
	rec := httptest.NewRecorder()
	h.deleteTenant(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete tenant: %d", rec.Code)
	}

	if _, ok, _ := h.store.ValidateSession(context.Background(), "tok-acme"); ok {
		t.Error("session for the deleted tenant must be revoked, not just left to expire on TTL")
	}
}

func TestTenants_CannotDeleteDefault(t *testing.T) {
	h := freshHandlers(t)
	ctx := ctxAs("default", iam.RoleAdmin, true)
	r := httptest.NewRequest(http.MethodDelete, "/api/tenants/default", nil)
	r = r.WithContext(ctx)
	r.SetPathValue("id", "default")
	rec := httptest.NewRecorder()
	h.deleteTenant(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete default: %d, want 400", rec.Code)
	}
}

// — Users —

func TestUsers_AdminCreatesInOwnTenant(t *testing.T) {
	h := freshHandlers(t)
	// super-admin seeds the tenant
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants",
		ctxAs("default", iam.RoleAdmin, true), map[string]any{"id": "acme"})

	ctx := ctxAs("acme", iam.RoleAdmin, false)
	rec, body := doReq(h.createUser, http.MethodPost, "/api/users", ctx, map[string]any{
		"email": "ops@acme.io", "password": "longlonglonglong", "role": "viewer",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("createUser in own tenant: %d, body=%v", rec.Code, body)
	}
	if body["tenant"] != "acme" {
		t.Fatalf("user tenant = %v, want acme", body["tenant"])
	}
}

func TestUsers_AdminCannotCreateInOtherTenant(t *testing.T) {
	h := freshHandlers(t)
	su := ctxAs("default", iam.RoleAdmin, true)
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "acme"})
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "globex"})

	// acme admin tries to create a globex user — forbidden.
	rec, _ := doReq(h.createUser, http.MethodPost, "/api/users",
		ctxAs("acme", iam.RoleAdmin, false), map[string]any{
			"email": "intruder@globex.io", "password": "longlonglonglong", "tenant": "globex",
		})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant createUser: %d, want 403", rec.Code)
	}
}

func TestUsers_OrdinaryAdminCannotGrantSuperAdmin(t *testing.T) {
	h := freshHandlers(t)
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants",
		ctxAs("default", iam.RoleAdmin, true), map[string]any{"id": "acme"})
	rec, _ := doReq(h.createUser, http.MethodPost, "/api/users",
		ctxAs("acme", iam.RoleAdmin, false), map[string]any{
			"email": "x@acme.io", "password": "longlonglonglong", "super_admin": true,
		})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-super granting super: %d, want 403", rec.Code)
	}
}

func TestUsers_WeakPasswordRejected(t *testing.T) {
	h := freshHandlers(t)
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants",
		ctxAs("default", iam.RoleAdmin, true), map[string]any{"id": "acme"})
	rec, _ := doReq(h.createUser, http.MethodPost, "/api/users",
		ctxAs("acme", iam.RoleAdmin, false), map[string]any{
			"email": "x@acme.io", "password": "short",
		})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short password: %d, want 400", rec.Code)
	}
}

func TestUsers_AdminListSeesOnlyOwnTenant(t *testing.T) {
	h := freshHandlers(t)
	su := ctxAs("default", iam.RoleAdmin, true)
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "acme"})
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "globex"})
	_, _ = doReq(h.createUser, http.MethodPost, "/api/users", su, map[string]any{
		"email": "a@acme.io", "password": "longlonglonglong", "tenant": "acme",
	})
	_, _ = doReq(h.createUser, http.MethodPost, "/api/users", su, map[string]any{
		"email": "g@globex.io", "password": "longlonglonglong", "tenant": "globex",
	})

	// acme admin tries to peek into globex by passing ?tenant=globex — must be
	// silently coerced to their own tenant.
	r := httptest.NewRequest(http.MethodGet, "/api/users?tenant=globex", nil)
	r = r.WithContext(ctxAs("acme", iam.RoleAdmin, false))
	rec := httptest.NewRecorder()
	h.listUsers(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("listUsers: %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	us, _ := body["users"].([]any)
	if len(us) != 1 {
		t.Fatalf("admin saw %d users, want 1 (own tenant)", len(us))
	}
	first, _ := us[0].(map[string]any)
	if first["tenant_id"] != "acme" {
		t.Fatalf("admin leaked into %q", first["tenant_id"])
	}
}

func TestUsers_CrossTenantDeleteForbidden(t *testing.T) {
	h := freshHandlers(t)
	su := ctxAs("default", iam.RoleAdmin, true)
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "acme"})
	_, _ = doReq(h.createTenant, http.MethodPost, "/api/tenants", su, map[string]any{"id": "globex"})
	_, gxBody := doReq(h.createUser, http.MethodPost, "/api/users", su, map[string]any{
		"email": "g@globex.io", "password": "longlonglonglong", "tenant": "globex",
	})
	gxID, _ := gxBody["id"].(string)
	if gxID == "" {
		t.Fatal("could not seed globex user")
	}

	// acme admin tries to delete a globex user — must be 403 (and the deletion
	// must NOT happen; we verify by trying to list as super-admin afterwards).
	r := httptest.NewRequest(http.MethodDelete, "/api/users/"+gxID, nil)
	r = r.WithContext(ctxAs("acme", iam.RoleAdmin, false))
	r.SetPathValue("id", gxID)
	rec := httptest.NewRecorder()
	h.deleteUser(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant delete: %d, want 403", rec.Code)
	}

	// Confirm the user still exists.
	gxUsers, _ := h.users.ListUsers(context.Background(), "globex")
	if len(gxUsers) != 1 {
		t.Fatalf("globex users after blocked delete = %d, want 1", len(gxUsers))
	}
}

// TestUsers_CannotDeleteSelf locks in the lockout guard: an operator deleting
// their own user ID is refused with 400 before the store is ever touched.
func TestUsers_CannotDeleteSelf(t *testing.T) {
	h := freshHandlers(t)
	su := ctxAs("default", iam.RoleAdmin, true)
	_, body := doReq(h.createUser, http.MethodPost, "/api/users", su, map[string]any{
		"email": "me@default.io", "password": "longlonglonglong",
	})
	uid, _ := body["id"].(string)
	if uid == "" {
		t.Fatal("could not seed user")
	}

	// The same user, now authenticated as themselves, tries to delete their own
	// account.
	ctx := iam.WithUserID(ctxAs("default", iam.RoleAdmin, false), uid)
	r := httptest.NewRequest(http.MethodDelete, "/api/users/"+uid, nil)
	r = r.WithContext(ctx)
	r.SetPathValue("id", uid)
	rec := httptest.NewRecorder()
	h.deleteUser(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("self-delete: %d, want 400", rec.Code)
	}

	// Account must survive.
	us, _ := h.users.ListUsers(context.Background(), "default")
	if len(us) != 1 {
		t.Fatalf("users after blocked self-delete = %d, want 1", len(us))
	}
}

func TestUsers_DeleteRevokesLiveSessions(t *testing.T) {
	h := freshHandlers(t)
	su := ctxAs("default", iam.RoleAdmin, true)
	_, body := doReq(h.createUser, http.MethodPost, "/api/users", su, map[string]any{
		"email": "victim@default.io", "password": "longlonglonglong",
	})
	uid, _ := body["id"].(string)
	if uid == "" {
		t.Fatal("could not seed user")
	}

	sess := iam.Session{TenantID: "default", UserID: uid, Role: iam.RoleAdmin, CSRF: "csrf"}
	if err := h.store.CreateSession(context.Background(), "tok-victim", sess, time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	r := httptest.NewRequest(http.MethodDelete, "/api/users/"+uid, nil)
	r = r.WithContext(su)
	r.SetPathValue("id", uid)
	rec := httptest.NewRecorder()
	h.deleteUser(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete user: %d", rec.Code)
	}

	if _, ok, _ := h.store.ValidateSession(context.Background(), "tok-victim"); ok {
		t.Error("session for the deleted user must be revoked, not just left to expire on TTL")
	}
}
