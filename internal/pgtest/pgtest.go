// Package pgtest isolates PostgreSQL-backed integration tests by schema.
//
// `go test ./...` runs packages in PARALLEL, and all our integration tests
// point at the single database in POSTGRES_DSN. Several packages TRUNCATE the
// same tables (admin_users, api_endpoints, admin_audit_log, …) for a clean
// slate, so without isolation one package's TRUNCATE wipes another's rows
// mid-test and both flake. Rather than serialise the whole suite with `-p 1`
// (which slows CI and hides real regressions) or leave a footgun for anyone who
// runs `go test ./...` locally against a DB, each package routes its objects
// into its own schema via search_path — created here, torn down on cleanup.
package pgtest

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// DSN returns a connection string scoped to the dedicated schema `schema` (via
// the libpq startup parameter search_path), isolating this package from every
// other test package that shares the same database. It skips the test when
// POSTGRES_DSN is unset, keeping the default `go test ./...` hermetic. The
// schema is dropped and recreated so each run starts clean; a t.Cleanup drops
// it afterwards.
//
// WHICH ROLE IT CONNECTS AS, and why it matters more than it looks:
//
// A superuser — or any role with BYPASSRLS — ignores row-level security
// entirely. Every tenant-isolation policy in this codebase is then dead code
// during the test run, and a query that forgot its tenant filter passes exactly
// like one that did not. Measured on the seal work: two mutations that removed
// real protections stayed green under a superuser and went red the moment an
// ordinary role ran the same tests.
//
// So when POSTGRES_APP_DSN names an unprivileged role, that is what tests
// connect as, and POSTGRES_DSN is used only to manage the schema and grant the
// app role access to it. Tests that genuinely need superuser — the ones that
// CREATE ROLE to build a restricted connection of their own — ask for AdminDSN
// explicitly rather than quietly receiving one.
func DSN(t *testing.T, schema string) string {
	t.Helper()
	base := os.Getenv("POSTGRES_DSN")
	if base == "" {
		t.Skip("POSTGRES_DSN not set; skipping PostgreSQL integration test")
	}

	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("pgtest: open base DSN: %v", err)
	}
	defer func() { _ = admin.Close() }()
	q := pgx.Identifier{schema}.Sanitize()
	// Fresh schema per run: drops any tables a previous run left with an older
	// column set, so schema-migrating DDL in the stores starts from clean.
	if _, err := admin.Exec("DROP SCHEMA IF EXISTS " + q + " CASCADE"); err != nil {
		t.Fatalf("pgtest: drop schema %s: %v", schema, err)
	}
	if _, err := admin.Exec("CREATE SCHEMA " + q); err != nil {
		t.Fatalf("pgtest: create schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		db, err := sql.Open("pgx", base)
		if err != nil {
			return
		}
		defer func() { _ = db.Close() }()
		_, _ = db.Exec("DROP SCHEMA IF EXISTS " + q + " CASCADE")
	})

	app := os.Getenv("POSTGRES_APP_DSN")
	if app == "" {
		return withSearchPath(t, base, schema)
	}

	// The app role owns nothing, so it needs explicit rights on the schema the
	// admin just created — CREATE because the stores build their own tables.
	//
	// The role name is read back from the server rather than parsed out of the
	// DSN. Two reasons, and the second is the one that matters: the DSN's
	// userinfo is what we ASKED to be, current_user is what we ARE (a pg_ident
	// map or a peer rule can differ), and a name taken from the environment and
	// interpolated into DDL is a tainted path into SQL — correctly flagged as
	// such. What comes back here was produced by PostgreSQL itself.
	user := connectedUser(t, app)
	for _, stmt := range []string{
		"GRANT USAGE, CREATE ON SCHEMA " + q + " TO " + pgQuote(user),
		"ALTER DEFAULT PRIVILEGES IN SCHEMA " + q + " GRANT ALL ON TABLES TO " + pgQuote(user),
		"ALTER DEFAULT PRIVILEGES IN SCHEMA " + q + " GRANT ALL ON SEQUENCES TO " + pgQuote(user),
	} {
		if _, err := admin.Exec(stmt); err != nil {
			// Not a skip. POSTGRES_APP_DSN being set is a statement that this
			// environment intends to test under RLS; failing to arrange it is a
			// broken environment, and skipping here would hand back the silent
			// pass this whole mechanism exists to remove.
			t.Fatalf("pgtest: grant %s on schema %s to %s: %v", stmt, schema, user, err)
		}
	}
	return withSearchPath(t, app, schema)
}

// AdminDSN returns POSTGRES_DSN unchanged, scoped to `schema`.
//
// For the handful of tests that must act as a superuser — those that CREATE
// ROLE to open a deliberately restricted connection. Everything else takes
// DSN, which prefers the unprivileged role. Asking for admin is therefore a
// visible choice in the test that needs it, not the invisible default it used
// to be.
func AdminDSN(t *testing.T, schema string) string {
	t.Helper()
	base := os.Getenv("POSTGRES_DSN")
	if base == "" {
		t.Skip("POSTGRES_DSN not set; skipping PostgreSQL integration test")
	}
	return withSearchPath(t, base, schema)
}

// connectedUser opens the app DSN and asks PostgreSQL who it authenticated as.
func connectedUser(t *testing.T, dsn string) string {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("pgtest: open POSTGRES_APP_DSN: %v", err)
	}
	defer func() { _ = db.Close() }()

	var user string
	if err := db.QueryRow(`SELECT current_user`).Scan(&user); err != nil {
		t.Fatalf("pgtest: POSTGRES_APP_DSN is set but unusable (%v); "+
			"a broken app role must fail the run, not quietly fall back to the superuser", err)
	}

	// The role must be the thing it claims to be. A POSTGRES_APP_DSN that
	// happens to name a superuser puts the suite back where it started: green
	// checks with every RLS policy inert, and nothing saying so.
	var bypass bool
	if err := db.QueryRow(
		`SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		t.Fatalf("pgtest: cannot check the privileges of %s: %v", user, err)
	}
	if bypass {
		t.Fatalf("pgtest: POSTGRES_APP_DSN connects as %s, which bypasses row-level "+
			"security; the isolation tests would pass without proving anything", user)
	}
	return user
}

// pgQuote quotes an identifier for DDL that cannot take a placeholder.
func pgQuote(id string) string { return `"` + strings.ReplaceAll(id, `"`, `""`) + `"` }

// withSearchPath adds `search_path=<schema>` to the DSN. pgx forwards it as a
// startup parameter, so every pooled connection lands in the schema. Handles
// both URL DSNs (postgres://…) and libpq keyword/value DSNs.
func withSearchPath(t *testing.T, base, schema string) string {
	t.Helper()
	if strings.Contains(base, "://") {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatalf("pgtest: parse DSN: %v", err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	return base + " search_path=" + schema
}
