package retention

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/pgtest"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type nopLogger struct{}

func (nopLogger) Info(string, ...map[string]any)  {}
func (nopLogger) Error(string, ...map[string]any) {}

// setup creates the minimal schema the sweep touches inside an isolated test
// schema, mirroring the real tables (including RLS on forensic/consumer tables
// with the documented '*' escape hatch) so the test proves the maintenance path
// actually deletes across tenants under FORCE ROW LEVEL SECURITY. It returns a
// Worker built directly over the shared *sql.DB plus the isolated DSN, so tests
// can also exercise the New(dsn) constructor path.
func setup(t *testing.T) (*Worker, *sql.DB, string) {
	t.Helper()
	dsn := pgtest.DSN(t, "test_retention")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	createTables(t, db)
	return &Worker{db: db, cfg: config.RetentionConfig{}, log: nopLogger{}}, db, dsn
}

func createTables(t *testing.T, db *sql.DB) {
	t.Helper()
	ddl := []string{
		`CREATE TABLE forensic_logs (id BIGSERIAL PRIMARY KEY, tenant_id TEXT NOT NULL DEFAULT 'default', ts TIMESTAMPTZ NOT NULL)`,
		`ALTER TABLE forensic_logs ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE forensic_logs FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY p ON forensic_logs USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '*') WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '*')`,
		`CREATE TABLE admin_audit_log (id BIGSERIAL PRIMARY KEY, tenant_id TEXT NOT NULL DEFAULT 'default', ts TIMESTAMPTZ NOT NULL)`,
		`CREATE TABLE api_consumers (tenant_id TEXT NOT NULL DEFAULT 'default', id TEXT NOT NULL, last_seen TIMESTAMPTZ NOT NULL, PRIMARY KEY (tenant_id, id))`,
		`ALTER TABLE api_consumers ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE api_consumers FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY p ON api_consumers USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '*') WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '*')`,
		`CREATE TABLE api_endpoint_consumers (tenant_id TEXT NOT NULL DEFAULT 'default', endpoint_id TEXT NOT NULL, consumer_id TEXT NOT NULL, last_seen TIMESTAMPTZ NOT NULL, PRIMARY KEY (tenant_id, endpoint_id, consumer_id))`,
		`ALTER TABLE api_endpoint_consumers ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE api_endpoint_consumers FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY p ON api_endpoint_consumers USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '*') WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '*')`,
	}
	for _, q := range ddl {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("ddl %q: %v", q, err)
		}
	}
}

// seed inserts a row with a given age (days ago) via the '*' GUC so RLS lets the
// insert through regardless of tenant.
func spanExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.tenant_id','*',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(q, args...); err != nil {
		t.Fatalf("seed %q: %v", q, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	tx, _ := db.Begin()
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.Exec(`SELECT set_config('app.tenant_id','*',true)`)
	if err := tx.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestSweep_DeletesAgedRowsAcrossTenants(t *testing.T) {
	w, db, _ := setup(t)
	w.cfg = config.RetentionConfig{ForensicDays: 90, AuditDays: 365, ConsumerIdleDays: 90}
	now := time.Now()
	old := now.AddDate(0, 0, -400)   // beyond every window (max is audit 365)
	recent := now.AddDate(0, 0, -10) // within every window

	// Two tenants, to prove the '*' maintenance path spans RLS.
	spanExec(t, db, `INSERT INTO forensic_logs (tenant_id, ts) VALUES ('default',$1),('acme',$1),('default',$2)`, old, recent)
	spanExec(t, db, `INSERT INTO admin_audit_log (tenant_id, ts) VALUES ('default',$1),('acme',$2)`, old, recent)
	spanExec(t, db, `INSERT INTO api_consumers (tenant_id, id, last_seen) VALUES ('default','c-old',$1),('acme','c-old',$1),('default','c-new',$2)`, old, recent)
	// Edges: e1/c-old is idle → deleted by the last_seen pass; e1/c-new is recent
	// and its consumer survives → kept; e2/c-old is RECENT (survives the idle
	// pass) but its consumer c-old is purged → deleted by the orphan pass.
	spanExec(t, db, `INSERT INTO api_endpoint_consumers (tenant_id, endpoint_id, consumer_id, last_seen) VALUES ('default','e1','c-old',$1),('default','e1','c-new',$2),('default','e2','c-old',$2)`, old, recent)

	st, err := w.sweepAt(context.Background(), now)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if st.Forensic != 2 { // two old across two tenants
		t.Fatalf("forensic deleted = %d, want 2", st.Forensic)
	}
	if got := count(t, db, "forensic_logs"); got != 1 {
		t.Fatalf("forensic_logs remaining = %d, want 1", got)
	}
	if st.Audit != 1 {
		t.Fatalf("audit deleted = %d, want 1", st.Audit)
	}
	if st.Consumers != 2 {
		t.Fatalf("consumers deleted = %d, want 2", st.Consumers)
	}
	// One idle edge (last_seen old) + one orphan edge (c-old purged) = 2.
	if st.ConsumerEdges != 2 {
		t.Fatalf("consumer edges deleted = %d, want 2", st.ConsumerEdges)
	}
	if got := count(t, db, "api_endpoint_consumers"); got != 1 {
		t.Fatalf("edges remaining = %d, want 1 (the recent c-new edge)", got)
	}
	if got := count(t, db, "api_consumers"); got != 1 {
		t.Fatalf("consumers remaining = %d, want 1", got)
	}
}

func TestSweep_ZeroWindowSkipsTable(t *testing.T) {
	w, db, _ := setup(t)
	w.cfg = config.RetentionConfig{ForensicDays: 0, AuditDays: 30, ConsumerIdleDays: 0}
	old := time.Now().AddDate(0, 0, -100)
	spanExec(t, db, `INSERT INTO forensic_logs (tenant_id, ts) VALUES ('default',$1)`, old)
	spanExec(t, db, `INSERT INTO admin_audit_log (tenant_id, ts) VALUES ('default',$1)`, old)

	st, err := w.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if st.Forensic != 0 {
		t.Fatalf("forensic_days=0 must skip; deleted %d", st.Forensic)
	}
	if count(t, db, "forensic_logs") != 1 {
		t.Fatal("forensic row must survive when forensic_days=0")
	}
	if st.Audit != 1 {
		t.Fatalf("audit_days=30 must prune the 100-day-old row; deleted %d", st.Audit)
	}
}

// TestNew_RunSweepClose exercises the constructor's own pool, the Run loop's
// immediate sweep, cancellation, and Close.
func TestNew_RunSweepClose(t *testing.T) {
	_, db, dsn := setup(t)
	old := time.Now().AddDate(0, 0, -100)
	spanExec(t, db, `INSERT INTO forensic_logs (tenant_id, ts) VALUES ('default',$1)`, old)

	w, err := New(dsn, config.RetentionConfig{Interval: time.Hour, ForensicDays: 90}, nopLogger{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	// Run sweeps once immediately, then blocks on the ticker; cancel returns it.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	// Poll for the immediate sweep to have deleted the aged row.
	deadline := time.Now().Add(5 * time.Second)
	for count(t, db, "forensic_logs") != 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run did not perform its immediate sweep")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop on context cancel")
	}
}

func TestNew_BadDSN(t *testing.T) {
	if _, err := New("postgres://bad:bad@127.0.0.1:1/none?sslmode=disable&connect_timeout=1",
		config.RetentionConfig{ForensicDays: 1}, nopLogger{}); err == nil {
		t.Fatal("New must error on an unreachable database")
	}
}
