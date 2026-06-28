package discovery

import (
	"context"
	"database/sql"
	"testing"
)

// skipIfRLSBypassed skips when the connected PostgreSQL role bypasses Row-Level
// Security (a superuser or a BYPASSRLS role). RLS simply does not engage for such
// a role, so the assertions below cannot hold: the CI postgres service runs as
// the `postgres` superuser, whereas a production / home-server app role is
// non-privileged and does enforce RLS. Mirrors newPGStore's startup warning.
func skipIfRLSBypassed(t *testing.T, s *pgStore) {
	t.Helper()
	var bypass bool
	if err := s.db.QueryRow(
		`SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&bypass); err != nil {
		t.Fatalf("role capability check: %v", err)
	}
	if bypass {
		t.Skip("connected role bypasses RLS (superuser/BYPASSRLS); RLS is validated with a non-privileged app role")
	}
}

// TestPG_RLS_FailsClosedWithoutGUC is the acceptance test for ADR phase 2b:
// even a SELECT that "forgets" the WHERE tenant_id filter must return zero
// rows for any tenant other than the one pinned via app.tenant_id. This
// protects against forgotten filters and SQL-injection peek-attempts.
func TestPG_RLS_FailsClosedWithoutGUC(t *testing.T) {
	s := freshStore(t)
	skipIfRLSBypassed(t, s)
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
	s := freshStore(t)
	skipIfRLSBypassed(t, s)
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
