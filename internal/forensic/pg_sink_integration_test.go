package forensic

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"api-gateway/internal/pgtest"
	"api-gateway/internal/store"
)

type nopLogger struct{}

func (nopLogger) Info(string, ...map[string]any)  {}
func (nopLogger) Error(string, ...map[string]any) {}

// writeEntries pushes entries through a dedicated short-lived sink and Closes
// it. Close is the one genuinely deterministic flush the sink offers: it stops
// the background worker (which drains and flushes on the way out) and then
// drains once more itself, so every entry is durable by the time it returns.
//
// This replaces an earlier `s.flush(s.drain())` that a comment called
// "deterministic" and wasn't: the background flushWorker races the caller for
// the channel, so it can pull an entry into its own private in-flight batch
// before drain() runs, leaving that entry invisible until the worker's 3s
// tick. That test passed on luck and went red the first time -race changed the
// scheduling. Polling for the row would also work, but it pays that 3s tick on
// every test; going through Close costs nothing and needs no timeout at all.
func writeEntries(t *testing.T, dsn string, entries ...store.ForensicEntry) {
	t.Helper()
	w, err := NewPGSink(dsn, nopLogger{})
	if err != nil {
		t.Fatalf("NewPGSink (writer): %v", err)
	}
	for _, e := range entries {
		w.Push(e)
	}
	w.Close() // drains + flushes everything before returning
}

// testSink returns a reader sink plus the DSN it is bound to (so a test can
// create a writer against the same schema via writeEntries).
func testSink(t *testing.T) (*PGSink, string) {
	t.Helper()
	dsn := pgtest.DSN(t, "test_forensic")
	s, err := NewPGSink(dsn, nopLogger{})
	if err != nil {
		t.Fatalf("NewPGSink: %v", err)
	}
	t.Cleanup(s.Close)
	return s, dsn
}

func TestNewPGSink_ConnectsAndMigrates(t *testing.T) {
	s, _ := testSink(t)
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'forensic_logs')`).Scan(&exists)
	if err != nil {
		t.Fatalf("check table exists: %v", err)
	}
	if !exists {
		t.Fatal("NewPGSink must create the forensic_logs table")
	}
}

func TestNewPGSink_RejectsBadDSN(t *testing.T) {
	if _, err := NewPGSink("postgres://nobody:nowhere@127.0.0.1:1/doesnotexist?sslmode=disable&connect_timeout=1", nopLogger{}); err == nil {
		t.Fatal("expected an error connecting to an unreachable DSN")
	}
}

// TestPGSink_PushThenCloseFlushesAllEntries relies on Close's documented
// behavior: it stops the background worker (which itself drains and flushes
// on shutdown) and then performs one more drain+flush of anything left, so by
// the time Close returns every Push'd entry is guaranteed durable. No sleep
// or polling needed — this exercises exactly that guarantee.
func TestPGSink_PushThenCloseFlushesAllEntries(t *testing.T) {
	dsn := pgtest.DSN(t, "test_forensic_flush")
	s, err := NewPGSink(dsn, nopLogger{})
	if err != nil {
		t.Fatalf("NewPGSink: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	s.Push(store.ForensicEntry{Tenant: "acme", Timestamp: now, IP: "1.2.3.4", Path: "/x", Method: "GET", Reason: "waf_block", Code: 403})
	s.Push(store.ForensicEntry{Tenant: "acme", Timestamp: now, IP: "5.6.7.8", Path: "/y", Method: "POST", Reason: "rate_limited", Code: 429})
	s.Close() // must flush both entries before returning

	// Re-open a plain *sql.DB against the same DSN (s.db is closed by now) to
	// verify persistence independent of QueryLogs, which is tested separately.
	// set_config(..., is_local=true) only lasts for the current transaction —
	// *sql.DB is a pool, so a bare Exec (auto-committed) followed by a bare
	// QueryRow can land on two different pooled connections, silently losing
	// the GUC in between. An explicit transaction (matching how pg_sink.go's
	// own flush/QueryLogs do it) pins both statements to the same connection.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer func() { _ = db.Close() }()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.tenant_id', 'acme', true)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM forensic_logs WHERE tenant_id = 'acme'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("persisted rows = %d, want 2", count)
	}
}

func TestPGSink_QueryLogs_FiltersByTenantIPAndReason(t *testing.T) {
	s, dsn := testSink(t)
	now := time.Now().UTC()

	writeEntries(t, dsn,
		store.ForensicEntry{Tenant: "acme", Timestamp: now, IP: "1.1.1.1", Path: "/a", Method: "GET", Reason: "waf_block", Code: 403},
		store.ForensicEntry{Tenant: "acme", Timestamp: now.Add(time.Second), IP: "2.2.2.2", Path: "/b", Method: "GET", Reason: "rate_limited", Code: 429},
		store.ForensicEntry{Tenant: "globex", Timestamp: now, IP: "1.1.1.1", Path: "/c", Method: "GET", Reason: "waf_block", Code: 403},
	)

	acme, err := s.QueryLogs(context.Background(), "acme", 10, "", "")
	if err != nil {
		t.Fatalf("QueryLogs acme: %v", err)
	}
	if len(acme) != 2 {
		t.Fatalf("acme entries = %d, want 2 (tenant isolation)", len(acme))
	}
	for _, e := range acme {
		if e.Tenant != "acme" {
			t.Fatalf("cross-tenant leak: got tenant %q in an acme-scoped query", e.Tenant)
		}
	}

	byIP, err := s.QueryLogs(context.Background(), "acme", 10, "2.2.2.2", "")
	if err != nil {
		t.Fatalf("QueryLogs by IP: %v", err)
	}
	if len(byIP) != 1 || byIP[0].IP != "2.2.2.2" {
		t.Fatalf("IP filter wrong: %+v", byIP)
	}

	byReason, err := s.QueryLogs(context.Background(), "acme", 10, "", "waf_block")
	if err != nil {
		t.Fatalf("QueryLogs by reason: %v", err)
	}
	if len(byReason) != 1 || byReason[0].Reason != "waf_block" {
		t.Fatalf("reason filter wrong: %+v", byReason)
	}

	// Newest first.
	all, err := s.QueryLogs(context.Background(), "acme", 10, "", "")
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if len(all) == 2 && !all[0].Timestamp.After(all[1].Timestamp) {
		t.Errorf("expected newest-first ordering, got %v then %v", all[0].Timestamp, all[1].Timestamp)
	}
}

func TestPGSink_QueryLogs_RespectsLimit(t *testing.T) {
	s, dsn := testSink(t)
	now := time.Now().UTC()
	var batch []store.ForensicEntry
	for i := 0; i < 5; i++ {
		batch = append(batch, store.ForensicEntry{Tenant: "acme", Timestamp: now.Add(time.Duration(i) * time.Second), IP: "1.1.1.1", Path: "/a", Method: "GET", Reason: "waf_block", Code: 403})
	}
	writeEntries(t, dsn, batch...) // all 5 durable before asserting the LIMIT caps the result

	got, err := s.QueryLogs(context.Background(), "acme", 3, "", "")
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3 (limit)", len(got))
	}
}

func TestPGSink_MissingTenantDefaultsToDefault(t *testing.T) {
	s, dsn := testSink(t)
	writeEntries(t, dsn, store.ForensicEntry{Timestamp: time.Now().UTC(), IP: "1.1.1.1", Path: "/a", Method: "GET", Reason: "waf_block", Code: 403}) // Tenant: ""

	got, err := s.QueryLogs(context.Background(), "default", 10, "", "")
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entries under 'default' = %d, want 1 (empty tenant must backfill to 'default')", len(got))
	}
}

func TestPGSink_QueryLogsEmptyTenantDefaultsToDefault(t *testing.T) {
	s, dsn := testSink(t)
	writeEntries(t, dsn, store.ForensicEntry{Tenant: "default", Timestamp: time.Now().UTC(), IP: "1.1.1.1", Path: "/a", Method: "GET", Reason: "x", Code: 200})

	got, err := s.QueryLogs(context.Background(), "", 10, "", "") // tenantID: "" -> should behave like "default"
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1", len(got))
	}
}

// skipIfRLSBypassed skips when the connected PostgreSQL role bypasses
// Row-Level Security (a superuser, or one with BYPASSRLS). RLS never engages
// for such a role, so a fail-closed assertion cannot hold — CI's postgres
// service runs as the `postgres` superuser, while a production or home-server
// app role is non-privileged and does enforce it. Same guard, and the same
// reasoning, as internal/discovery/store_pg_rls_test.go; duplicated rather
// than shared because both live in _test files of different packages.
func skipIfRLSBypassed(t *testing.T, db *sql.DB) {
	t.Helper()
	var bypass bool
	if err := db.QueryRow(
		`SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&bypass); err != nil {
		t.Fatalf("role capability check: %v", err)
	}
	if bypass {
		t.Skip("connected role bypasses RLS (superuser/BYPASSRLS); RLS is validated with a non-privileged app role")
	}
}

// TestPGSink_RLSFailsClosedWithoutGUC mirrors the fail-closed RLS backstop
// already proven for the catalog tables (store_pg_rls_test.go): a query that
// never sets app.tenant_id must see zero rows, not every tenant's data.
func TestPGSink_RLSFailsClosedWithoutGUC(t *testing.T) {
	dsn := pgtest.DSN(t, "test_forensic_rls")
	// The row must actually be durable, or the "0 unscoped rows" assertion
	// below would pass vacuously against an empty table.
	writeEntries(t, dsn, store.ForensicEntry{Tenant: "acme", Timestamp: time.Now().UTC(), IP: "1.1.1.1", Path: "/a", Method: "GET", Reason: "x", Code: 200})

	// A separate, unscoped connection: never calls set_config, so RLS's
	// current_setting('app.tenant_id', true) is NULL/empty, matching neither
	// 'acme' nor '*'.
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer func() { _ = raw.Close() }()
	skipIfRLSBypassed(t, raw)
	var count int
	if err := raw.QueryRow(`SELECT count(*) FROM forensic_logs`).Scan(&count); err != nil {
		t.Fatalf("unscoped count: %v", err)
	}
	if count != 0 {
		t.Fatalf("unscoped read saw %d rows, want 0 (RLS must fail closed without app.tenant_id set)", count)
	}
}
