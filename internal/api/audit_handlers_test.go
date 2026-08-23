package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// freshHandlersWithAudit is freshHandlers plus a real (Postgres-backed)
// audit.Store, built from a SINGLE pgDSN(t) call. pgtest.DSN drops and
// recreates its schema on every call — calling it twice in one test (once
// for iam.NewStore via freshHandlers, once more here for audit.New) would
// wipe the tables the first call's store just created, so this must not
// call freshHandlers and then pgDSN(t) again; it builds both stores against
// the one DSN instead.
func freshHandlersWithAudit(t *testing.T) *handlers {
	t.Helper()
	dsn := pgDSN(t)

	iamStore, err := iam.NewStore(dsn, logger.New("error"))
	if err != nil {
		t.Fatalf("iam.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = iamStore.Close() })

	auditStore, err := audit.New(dsn, logger.New("error"))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })

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

	cfg := config.GatewayConfig{AdminAuth: false, AdminSecret: "test-secret-min-32-characters-1234"}
	return &handlers{
		store: redisStore,
		log:   logger.New("error"),
		cfg:   cfg,
		users: iamStore,
		audit: auditStore,
	}
}

// waitForAuditAction polls the audit log until an entry with the given action
// appears, or fails after a short deadline. Record() feeds an async worker, so
// a plain single List() right after the handler call would be flaky.
func waitForAuditAction(t *testing.T, h *handlers, action string) audit.Entry {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, err := h.audit.List(context.Background(), audit.Filter{TenantID: "*"})
		if err != nil {
			t.Fatalf("audit.List: %v", err)
		}
		for _, e := range entries {
			if e.Action == action {
				return e
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for audit action %q", action)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A super-admin reading another tenant's user list is exactly the kind of
// cross-tenant access an auditor needs visibility into, even though it's a
// GET and ordinary reads are deliberately not audited (see serveAndAudit).
func TestUsers_CrossTenantListIsAudited(t *testing.T) {
	h := freshHandlersWithAudit(t)

	ctx := iam.WithUserID(ctxAs("default", iam.RoleAdmin, true), "super-1")
	rec, _ := doReq(h.listUsers, http.MethodGet, "/api/users?tenant=other-tenant", ctx, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("listUsers: got %d, want 200", rec.Code)
	}

	e := waitForAuditAction(t, h, "cross_tenant_users_read")
	if e.ActorID != "super-1" {
		t.Errorf("audit entry actor = %q, want super-1", e.ActorID)
	}
	if e.Detail != "target_tenant=other-tenant" {
		t.Errorf("audit entry detail = %q, want target_tenant=other-tenant", e.Detail)
	}
}

// A super-admin reading their own tenant's user list is NOT a cross-tenant
// read and must not be logged as one.
func TestUsers_SameTenantListIsNotAudited(t *testing.T) {
	h := freshHandlersWithAudit(t)

	ctx := iam.WithUserID(ctxAs("default", iam.RoleAdmin, true), "super-1")
	rec, _ := doReq(h.listUsers, http.MethodGet, "/api/users?tenant=default", ctx, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("listUsers: got %d, want 200", rec.Code)
	}

	// Give the (absent) async write a moment, then confirm nothing landed.
	time.Sleep(150 * time.Millisecond)
	entries, err := h.audit.List(context.Background(), audit.Filter{TenantID: "*"})
	if err != nil {
		t.Fatalf("audit.List: %v", err)
	}
	for _, e := range entries {
		if e.Action == "cross_tenant_users_read" {
			t.Fatalf("same-tenant read must not be audited as cross-tenant, got entry: %+v", e)
		}
	}
}

func TestTenants_ListBySuperAdminIsAudited(t *testing.T) {
	h := freshHandlersWithAudit(t)

	ctx := iam.WithUserID(ctxAs("default", iam.RoleAdmin, true), "super-1")
	rec, _ := doReq(h.listTenants, http.MethodGet, "/api/tenants", ctx, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("listTenants: got %d, want 200", rec.Code)
	}

	waitForAuditAction(t, h, "cross_tenant_tenants_read")
}

func TestAudit_CrossTenantAllIsAudited(t *testing.T) {
	h := freshHandlersWithAudit(t)

	ctx := iam.WithUserID(ctxAs("default", iam.RoleAdmin, true), "super-1")
	rec, _ := doReq(h.getAudit, http.MethodGet, "/api/audit?all=true", ctx, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getAudit: got %d, want 200", rec.Code)
	}

	waitForAuditAction(t, h, "cross_tenant_audit_read")
}
