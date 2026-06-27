package iam

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"golang.org/x/crypto/bcrypt"
)

// ErrUserNotFound is returned when a lookup or VerifyPassword finds no matching
// user. Callers must treat it the same as a wrong password (constant-time
// behaviour from the outside) to avoid leaking which emails exist.
var ErrUserNotFound = errors.New("iam: user not found")

// Tenant is one organisation that owns its own catalog, blocklists, sessions
// and forensic logs. Mapped to the catalog/Redis isolation done in ADR phases
// 2–3 via TenantID == tenant.From(ctx).
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// User is a console operator. Password is stored as a bcrypt hash. SuperAdmin
// users are allowed to manage tenants and inspect any tenant's data; everyone
// else is locked to their own tenant.
type User struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	SuperAdmin   bool      `json:"super_admin"`
	CreatedAt    time.Time `json:"created_at"`
}

// Logger is the minimal logging interface the user store needs.
type Logger interface {
	Info(msg string, fields ...map[string]any)
	Error(msg string, fields ...map[string]any)
}

// schema is created on every connect and is idempotent so an existing
// deployment migrates cleanly without manual intervention.
const schema = `
CREATE TABLE IF NOT EXISTS tenants (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_users (
	id            TEXT PRIMARY KEY,
	tenant_id     TEXT NOT NULL,
	email         TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL DEFAULT 'admin',
	super_admin   BOOLEAN NOT NULL DEFAULT FALSE,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Email is unique per tenant (the same operator may legitimately exist in two
-- tenants with the same email — they are separate accounts).
CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_users_email ON admin_users (tenant_id, lower(email));
CREATE INDEX IF NOT EXISTS idx_admin_users_tenant ON admin_users (tenant_id);
`

// Store is a PostgreSQL-backed identity store for tenants and admin users.
type Store struct {
	db  *sql.DB
	log Logger
}

// NewStore connects to PostgreSQL, runs the idempotent schema, and returns a
// ready-to-use store. The DSN is shared with the forensic / catalog DB on
// purpose: one database, one operational footprint.
func NewStore(dsn string, log Logger) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("iam: pg connect: %w", err)
	}
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("iam: pg ping: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("iam: pg migrate: %w", err)
	}
	return &Store{db: db, log: log}, nil
}

// Close releases the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

// ── Tenants ─────────────────────────────────────────────────────────────────

// CreateTenant inserts a tenant if it does not exist yet (idempotent).
func (s *Store) CreateTenant(ctx context.Context, id, name string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, $2)
		 ON CONFLICT (id) DO NOTHING`, id, name)
	return err
}

// ListTenants returns all known tenants.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Tenant{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTenant removes a tenant and (cascadingly) all its users. Catalog and
// forensic data carry their own tenant_id but are NOT cascaded here — those
// rows survive deletion as historical records; only the IAM rows are removed.
// Returns (false, nil) if the tenant did not exist (idempotent).
func (s *Store) DeleteTenant(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_users WHERE tenant_id = $1`, id); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// ── Users ───────────────────────────────────────────────────────────────────

// CreateUser inserts a new user. Password is hashed with bcrypt before storage;
// the plaintext never reaches the database.
func (s *Store) CreateUser(ctx context.Context, u User, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("iam: hash password: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO admin_users (id, tenant_id, email, password_hash, role, super_admin)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		u.ID, u.TenantID, strings.ToLower(u.Email), string(hash), string(u.Role), u.SuperAdmin)
	return err
}

// VerifyPassword looks up a user by tenant+email and verifies the password.
// On success returns the user. On any failure (no such user, wrong password,
// DB error) returns ErrUserNotFound so the caller cannot distinguish — this
// prevents user-enumeration via the login endpoint.
func (s *Store) VerifyPassword(ctx context.Context, tenantID, email, password string) (User, error) {
	var u User
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, email, password_hash, role, super_admin, created_at
		 FROM admin_users WHERE tenant_id = $1 AND lower(email) = lower($2)`,
		tenantID, email,
	).Scan(&u.ID, &u.TenantID, &u.Email, &hash, &u.Role, &u.SuperAdmin, &u.CreatedAt)
	if err != nil {
		// Run a dummy bcrypt compare to keep timing roughly constant regardless
		// of whether the user exists, blunting timing-based user enumeration.
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$10$abcdefghijklmnopqrstuv1234567890123456789012345678901"),
			[]byte(password))
		return User{}, ErrUserNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return User{}, ErrUserNotFound
	}
	u.PasswordHash = "" // never return the hash
	return u, nil
}

// ListUsers returns all users in a tenant (or every tenant when tenantID is
// empty — only super-admins should invoke that form). Password hashes are
// stripped before returning.
func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, tenant_id, email, role, super_admin, created_at
			 FROM admin_users ORDER BY tenant_id, email`)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, tenant_id, email, role, super_admin, created_at
			 FROM admin_users WHERE tenant_id = $1 ORDER BY email`, tenantID)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.SuperAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser removes a single user. Returns (false, nil) when not found
// (idempotent) so a UI can issue the call safely.
func (s *Store) DeleteUser(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// CountUsers returns how many users exist in total. Used at startup to decide
// whether to bootstrap a root user.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&n)
	return n, err
}

// BootstrapRoot creates the default tenant and a super-admin user if (and only
// if) there are no users in the system yet. It is safe to call on every boot —
// once a user exists, subsequent calls do nothing.
func (s *Store) BootstrapRoot(ctx context.Context, tenantID, email, password string) error {
	n, err := s.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if err := s.CreateTenant(ctx, tenantID, tenantID); err != nil {
		return fmt.Errorf("iam: bootstrap tenant: %w", err)
	}
	u := User{
		ID:         "u-root",
		TenantID:   tenantID,
		Email:      email,
		Role:       RoleAdmin,
		SuperAdmin: true,
	}
	if err := s.CreateUser(ctx, u, password); err != nil {
		return fmt.Errorf("iam: bootstrap user: %w", err)
	}
	if s.log != nil {
		s.log.Info("iam: root user bootstrapped", map[string]any{"tenant": tenantID, "email": email})
	}
	return nil
}
