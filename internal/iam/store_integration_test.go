package iam

import (
	"context"
	"errors"
	"os"
	"testing"
)

// pgDSN returns the test PostgreSQL DSN or skips when unset.
func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set; skipping IAM integration test")
	}
	return dsn
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
