package incident

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
)

// asRestrictedRole returns a store connected as a freshly-created role that
// does NOT bypass Row-Level Security, so the policies below are actually
// exercised.
//
// The alternative — the pattern the rest of the repo uses — is to SKIP when the
// connected role bypasses RLS. That role is a superuser both on a default local
// cluster and in CI, where the service container runs as `postgres`. So the RLS
// assertions were skipped absolutely everywhere and verified nothing, while
// reading like a guarantee. Creating the role costs three statements.
//
// This also demonstrates the deployment requirement in docs/runbooks/ha.md:
// RLS protects nothing if the application connects as a superuser.
func asRestrictedRole(t *testing.T, s *PGStore) *PGStore {
	t.Helper()
	ctx := context.Background()

	const role = "aegis_rls_test"
	var schema string
	if err := s.db.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatalf("current_schema: %v", err)
	}
	var dbName string
	if err := s.db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatalf("current_database: %v", err)
	}

	for _, stmt := range []string{
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'rlstest' NOSUPERUSER NOBYPASSRLS`,
		`GRANT CONNECT ON DATABASE ` + pq(dbName) + ` TO ` + role,
		`GRANT USAGE ON SCHEMA ` + pq(schema) + ` TO ` + role,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON incidents TO ` + role,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			t.Skipf("cannot create a non-privileged role here (%v); RLS assertions need one", err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(`REVOKE ALL ON incidents FROM ` + role)
		_, _ = s.db.Exec(`REVOKE ALL ON SCHEMA ` + pq(schema) + ` FROM ` + role)
		_, _ = s.db.Exec(`REVOKE ALL ON DATABASE ` + pq(dbName) + ` FROM ` + role)
		_, _ = s.db.Exec(`DROP ROLE IF EXISTS ` + role)
	})

	dsn := rewriteUser(t, os.Getenv("POSTGRES_DSN"), role, "rlstest", schema)
	db, err := sql.Open("pgx", dsn)
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
	return &PGStore{db: db, log: nopLog{}}
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

// Without app.tenant_id pinned, a query that forgets its tenant filter must
// return nothing rather than everything. An incident row names an attacker, the
// endpoints they reached and the data those endpoints hold — the worst possible
// row to hand to the wrong tenant.
func TestPG_RLS_FailsClosedWithoutTheGUC(t *testing.T) {
	seed := newTestStore(t)
	s := asRestrictedRole(t, seed)
	ctx := context.Background()

	for _, tenant := range []string{"acme", "globex"} {
		mergeN(t, s, Delta{Tenant: tenant, Class: "bola", Subject: "u1", First: t0, Last: t0, Count: 1}, DefaultWindow)
	}

	// A raw connection with no GUC set: current_setting returns NULL, and
	// "tenant_id = NULL" is NULL, so the policy matches nothing.
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM incidents`).Scan(&n); err != nil {
		t.Fatalf("unscoped count: %v", err)
	}
	if n != 0 {
		t.Fatalf("an unscoped SELECT returned %d rows; RLS must fail closed", n)
	}
}

// The WITH CHECK half: a transaction pinned to one tenant must not be able to
// write a row belonging to another, even by naming it explicitly.
func TestPG_RLS_RejectsACrossTenantWrite(t *testing.T) {
	s := asRestrictedRole(t, newTestStore(t))
	ctx := context.Background()

	err := s.withTenantTx(ctx, "acme", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
INSERT INTO incidents (tenant_id, id, title, class, subject, detected_at, last_event_at)
VALUES ('globex','forged','forged','bola','u1',NOW(),NOW())`)
		return err
	})
	if err == nil {
		t.Fatal("a transaction pinned to acme inserted a row for globex")
	}
}

// FORCE ROW LEVEL SECURITY is what makes the policy apply to the table's OWNER.
// Plain ENABLE exempts the owner, and the gateway ordinarily connects as the
// role that created its tables — so without FORCE, RLS would be switched on and
// simultaneously inert in production.
//
// The two tests above cannot see this: their role has rights on the table but
// does not own it, so ENABLE alone already constrains it. Here ownership is
// handed over first, which is the only way the distinction becomes observable.
func TestPG_RLS_ForceAppliesToTheTableOwner(t *testing.T) {
	seed := newTestStore(t)
	s := asRestrictedRole(t, seed)
	ctx := context.Background()

	mergeN(t, seed, Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: t0, Last: t0, Count: 1}, DefaultWindow)

	if _, err := seed.db.ExecContext(ctx, `ALTER TABLE incidents OWNER TO aegis_rls_test`); err != nil {
		t.Skipf("cannot transfer table ownership here: %v", err)
	}
	t.Cleanup(func() {
		var owner string
		if seed.db.QueryRow(`SELECT current_user`).Scan(&owner) == nil {
			_, _ = seed.db.Exec(`ALTER TABLE incidents OWNER TO ` + pq(owner))
		}
	})

	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM incidents`).Scan(&n); err != nil {
		t.Fatalf("unscoped count as owner: %v", err)
	}
	if n != 0 {
		t.Fatalf("the table owner read %d rows with no tenant pinned; FORCE ROW LEVEL SECURITY is missing "+
			"and RLS is inert for the role the gateway actually connects as", n)
	}
}
