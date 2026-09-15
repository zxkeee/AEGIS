package discovery

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"api-gateway/internal/pgtest"
)

// asRestrictedRole returns a store connected as a freshly-created role that
// does NOT bypass Row-Level Security, so the policies below are actually
// exercised.
//
// This replaces skipIfRLSBypassed, which skipped whenever the connected role
// bypassed RLS. That role is a superuser on a default local cluster AND in CI,
// where the postgres service container runs as `postgres` — so these
// assertions were skipped everywhere they ran and verified nothing, while
// reading like a guarantee. internal/incident already made this change; this
// is the same fix for the catalog, which is the other half of the tenant
// isolation ADR-001 promises.
//
// It is not a hypothetical. A plain integration test in this package set row
// timestamps with a bare s.db.Exec, outside withTenantTx; under real RLS that
// UPDATE matches zero rows and returns no error, so the test asserted on data
// it never wrote — and passed, because the role bypassed RLS. That was only
// caught by running against a non-privileged role by accident.
//
// This also demonstrates the deployment requirement in docs/runbooks/ha.md:
// RLS protects nothing if the application connects as a superuser.
func asRestrictedRole(t *testing.T, s *pgStore) *pgStore {
	t.Helper()
	ctx := context.Background()

	const role = "aegis_discovery_rls_test"
	var schema, dbName string
	if err := s.db.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatalf("current_schema: %v", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatalf("current_database: %v", err)
	}

	// Admin connection for the role DDL. When ordinary tests run as an
	// unprivileged role (POSTGRES_APP_DSN), CREATE ROLE over the store's own
	// connection fails, and the old code skipped on that — so the environment
	// that actually enforces RLS ran fewer RLS assertions than the one that
	// does not.
	admin, err := sql.Open("pgx", pgtest.AdminDSN(t, schema))
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	// Every catalog table, not just api_endpoints: a policy that holds on one
	// table and not its neighbours is the gap this is meant to close.
	tables := []string{
		"api_endpoints", "api_endpoint_status", "api_consumers",
		"api_endpoint_consumers", "api_specs",
	}
	stmts := []string{
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'rlstest' NOSUPERUSER NOBYPASSRLS`,
		`GRANT CONNECT ON DATABASE ` + pq(dbName) + ` TO ` + role,
		`GRANT USAGE ON SCHEMA ` + pq(schema) + ` TO ` + role,
	}
	for _, tbl := range tables {
		stmts = append(stmts, `GRANT SELECT, INSERT, UPDATE, DELETE ON `+pq(tbl)+` TO `+role)
	}
	for _, stmt := range stmts {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("cannot create a non-privileged role (%v); RLS assertions need one, "+
				"and skipping here is how they came to verify nothing", err)
		}
	}
	t.Cleanup(func() {
		for _, tbl := range tables {
			_, _ = admin.Exec(`REVOKE ALL ON ` + pq(tbl) + ` FROM ` + role)
		}
		_, _ = admin.Exec(`REVOKE ALL ON SCHEMA ` + pq(schema) + ` FROM ` + role)
		_, _ = admin.Exec(`REVOKE ALL ON DATABASE ` + pq(dbName) + ` FROM ` + role)
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + role)
	})

	db, err := sql.Open("pgx", rewriteUser(t, os.Getenv("POSTGRES_DSN"), role, "rlstest", schema))
	if err != nil {
		t.Fatalf("open as %s: %v", role, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot connect as %s (%v); the cluster's auth rules do not allow it", role, err)
	}

	var bypass bool
	if err := db.QueryRowContext(ctx,
		`SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		t.Fatalf("role capability check: %v", err)
	}
	if bypass {
		t.Fatalf("%s was created NOSUPERUSER NOBYPASSRLS but still bypasses RLS", role)
	}
	return &pgStore{db: db, log: nopLogger{}}
}

// pq quotes an identifier for interpolation into DDL that cannot take a
// placeholder. The inputs are read back from PostgreSQL itself, but quoting
// them is the difference between a helper and a habit worth not forming.
func pq(id string) string { return `"` + strings.ReplaceAll(id, `"`, `""`) + `"` }

// rewriteUser points a DSN at a different role, keeping the search_path that
// pgtest set so the restricted connection lands in the same schema.
func rewriteUser(t *testing.T, dsn, user, pass, schema string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	u.User = url.UserPassword(user, pass)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// TestPG_RLS_FailsClosedWithoutGUC is the acceptance test for ADR phase 2b:
// even a SELECT that "forgets" the WHERE tenant_id filter must return zero
// rows for any tenant other than the one pinned via app.tenant_id. This
// protects against forgotten filters and SQL-injection peek-attempts.
func TestPG_RLS_FailsClosedWithoutGUC(t *testing.T) {
	seed := freshStore(t)
	s := asRestrictedRole(t, seed)
	ctx := context.Background()

	// Seed one row under each of two tenants.
	if err := s.upsertEndpoint(ctx, &epAgg{
		tenant: "acme", id: "GET:/x", method: "GET", pathTemplate: "/x",
		requestCount: 1, posture: "protected", statusDist: map[int]int64{200: 1},
	}); err != nil {
		t.Fatalf("seed acme: %v", err)
	}
	if err := s.upsertEndpoint(ctx, &epAgg{
		tenant: "globex", id: "GET:/x", method: "GET", pathTemplate: "/x",
		requestCount: 1, posture: "unprotected", statusDist: map[int]int64{500: 1},
	}); err != nil {
		t.Fatalf("seed globex: %v", err)
	}

	// 1. Direct connection without setting app.tenant_id — RLS must deny.
	//    No WHERE tenant_id filter on purpose: this simulates a forgotten scope.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_endpoints`).Scan(&n); err != nil {
		t.Fatalf("count without GUC: %v", err)
	}
	if n != 0 {
		t.Fatalf("RLS leak: SELECT without app.tenant_id saw %d rows; must see 0", n)
	}

	// 2. Inside a transaction pinned to acme, an unscoped SELECT still returns
	//    only acme's row. This is the key fail-closed guarantee: even if
	//    application code forgets to add WHERE tenant_id, RLS cuts it down.
	if err := s.withTenantTx(ctx, "acme", func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_endpoints`).Scan(&n)
	}); err != nil {
		t.Fatalf("count under acme GUC: %v", err)
	}
	if n != 1 {
		t.Fatalf("RLS over-restricts: acme saw %d rows, want 1", n)
	}

	// 3. Same query under globex — sees only globex's row.
	if err := s.withTenantTx(ctx, "globex", func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_endpoints`).Scan(&n)
	}); err != nil {
		t.Fatalf("count under globex GUC: %v", err)
	}
	if n != 1 {
		t.Fatalf("globex saw %d rows, want 1", n)
	}

	// 4. Maintenance escape hatch: app.tenant_id = '*' spans every tenant.
	if err := s.withTenantTx(ctx, "*", func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_endpoints`).Scan(&n)
	}); err != nil {
		t.Fatalf("count under '*': %v", err)
	}
	if n != 2 {
		t.Fatalf("wildcard saw %d rows, want 2", n)
	}
}

// TestPG_RLS_RejectsCrossTenantWrite verifies the WITH CHECK clause: an
// INSERT/UPDATE that tries to write rows belonging to a tenant other than
// the GUC-pinned one is rejected by PostgreSQL with an RLS violation.
func TestPG_RLS_RejectsCrossTenantWrite(t *testing.T) {
	s := asRestrictedRole(t, freshStore(t))
	ctx := context.Background()

	// Pin GUC to "acme" but attempt to insert tenant_id='globex'.
	err := s.withTenantTx(ctx, "acme", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO api_endpoints (tenant_id, id, method, path_template)
			 VALUES ('globex', 'GET:/y', 'GET', '/y')`)
		return err
	})
	if err == nil {
		t.Fatal("expected RLS to reject cross-tenant INSERT; it silently succeeded")
	}
}
