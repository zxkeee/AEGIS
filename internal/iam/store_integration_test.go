package iam

import (
	"context"
	"errors"
	"testing"

	"api-gateway/internal/pgtest"
)

// pgDSN returns a schema-isolated test PostgreSQL DSN (or skips when unset), so
// this package's TRUNCATEs never collide with other packages under `go test
// ./...`. See internal/pgtest.
func pgDSN(t *testing.T) string {
	t.Helper()
	return pgtest.DSN(t, "test_iam")
}

type nopLogger struct{}

func (nopLogger) Info(string, ...map[string]any)  {}
func (nopLogger) Error(string, ...map[string]any) {}

func freshIAM(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(pgDSN(t), nopLogger{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.Exec(`TRUNCATE admin_users, tenants`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestIAM_CreateAndVerify(t *testing.T) {
	s := freshIAM(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, "acme", "ACME"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	u := User{ID: "u1", TenantID: "acme", Email: "Op@Acme.io", Role: RoleAdmin}
	if err := s.CreateUser(ctx, u, "correct-horse"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Right password (case-insensitive email).
	got, err := s.VerifyPassword(ctx, "acme", "op@acme.io", "correct-horse")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if got.ID != "u1" || got.Role != RoleAdmin || got.PasswordHash != "" {
		t.Fatalf("verified user wrong: %+v", got)
	}

	// Wrong password → ErrUserNotFound (no enumeration leak).
	if _, err := s.VerifyPassword(ctx, "acme", "op@acme.io", "wrong"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("wrong password: %v, want ErrUserNotFound", err)
	}
	// Unknown email → same error.
	if _, err := s.VerifyPassword(ctx, "acme", "ghost@acme.io", "correct-horse"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: %v, want ErrUserNotFound", err)
	}
	// Wrong tenant → same error (cross-tenant isolation: tenant `globex` cannot
	// authenticate as acme's user).
	if _, err := s.VerifyPassword(ctx, "globex", "op@acme.io", "correct-horse"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant login leaked: %v, want ErrUserNotFound", err)
	}
}

func TestIAM_BootstrapRootIdempotent(t *testing.T) {
	s := freshIAM(t)
	ctx := context.Background()

	if err := s.BootstrapRoot(ctx, "default", "root@example.com", "init-pass"); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("expected 1 user after bootstrap, got %d", n)
	}

	// Second call must be a no-op (no duplicate user, no error).
	if err := s.BootstrapRoot(ctx, "default", "other@example.com", "other-pass"); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("bootstrap not idempotent: users=%d, want 1", n)
	}
	// The original root credentials still work — the second call did NOT
	// silently overwrite them.
	if _, err := s.VerifyPassword(ctx, "default", "root@example.com", "init-pass"); err != nil {
		t.Fatalf("original root creds invalidated: %v", err)
	}
}

func TestIAM_UpsertSSOUser(t *testing.T) {
	s := freshIAM(t)
	ctx := context.Background()

	// First SSO login: provisions the user and the tenant (JIT).
	u, err := s.UpsertSSOUser(ctx, "acme", "SSO@Acme.io", RoleViewer, false)
	if err != nil {
		t.Fatalf("UpsertSSOUser insert: %v", err)
	}
	if u.TenantID != "acme" || u.Role != RoleViewer || u.Email != "sso@acme.io" {
		t.Fatalf("provisioned user wrong: %+v", u)
	}

	// The SSO account can NEVER be used with password login (sentinel hash).
	if _, err := s.VerifyPassword(ctx, "acme", "sso@acme.io", ssoPasswordSentinel); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("SSO account accepted a password: %v", err)
	}
	if _, err := s.VerifyPassword(ctx, "acme", "sso@acme.io", "anything"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("SSO account accepted a password: %v", err)
	}

	// Returning login with elevated claims re-syncs role/super-admin in place
	// (same row, no duplicate).
	u2, err := s.UpsertSSOUser(ctx, "acme", "sso@acme.io", RoleAdmin, true)
	if err != nil {
		t.Fatalf("UpsertSSOUser update: %v", err)
	}
	if u2.ID != u.ID {
		t.Fatalf("re-login created a new row: %s vs %s", u2.ID, u.ID)
	}
	if u2.Role != RoleAdmin || !u2.SuperAdmin {
		t.Fatalf("role/super not re-synced: %+v", u2)
	}
	list, err := s.ListUsers(ctx, "acme")
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want exactly one user after re-login, got %d", len(list))
	}
}

// TestIAM_UpsertSSOUser_DoesNotConvertLocalAccount guards against account
// takeover: an OIDC login whose email collides with an existing LOCAL (password)
// account in the same tenant must be refused, not silently converted to SSO and
// re-privileged from IdP group claims.
func TestIAM_UpsertSSOUser_DoesNotConvertLocalAccount(t *testing.T) {
	s := freshIAM(t)
	ctx := context.Background()

	if err := s.CreateTenant(ctx, "acme", "ACME"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	local := User{ID: "u-local", TenantID: "acme", Email: "op@acme.io", Role: RoleAdmin, SuperAdmin: true}
	if err := s.CreateUser(ctx, local, "correct-horse-battery"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// OIDC login for the same tenant+email, mapped to a LOWER privilege, must be
	// rejected rather than downgrading/converting the local super-admin.
	if _, err := s.UpsertSSOUser(ctx, "acme", "OP@Acme.io", RoleViewer, false); err == nil {
		t.Fatal("expected UpsertSSOUser to refuse converting a local account")
	}

	// The local account is untouched: password still works, still super-admin.
	got, err := s.VerifyPassword(ctx, "acme", "op@acme.io", "correct-horse-battery")
	if err != nil {
		t.Fatalf("local account was disturbed: %v", err)
	}
	if got.ID != "u-local" || got.Role != RoleAdmin || !got.SuperAdmin {
		t.Fatalf("local account privileges changed: %+v", got)
	}
}
