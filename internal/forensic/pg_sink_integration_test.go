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
// it. Close is a genuinely deterministic flush: it stops the background worker
// (which drains and flushes on the way out) and then drains once more itself,
// so every entry is durable by the time it returns. Flush is the other one, and
// the right choice when the sink must stay open — it hands the work to the
// worker, which is the only goroutine that can reach the in-flight batch.
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

	acme, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "acme", Limit: 10, IP: "", Reason: ""})
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

	byIP, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "acme", Limit: 10, IP: "2.2.2.2", Reason: ""})
	if err != nil {
		t.Fatalf("QueryLogs by IP: %v", err)
	}
	if len(byIP) != 1 || byIP[0].IP != "2.2.2.2" {
		t.Fatalf("IP filter wrong: %+v", byIP)
	}

	byReason, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "acme", Limit: 10, IP: "", Reason: "waf_block"})
	if err != nil {
		t.Fatalf("QueryLogs by reason: %v", err)
	}
	if len(byReason) != 1 || byReason[0].Reason != "waf_block" {
		t.Fatalf("reason filter wrong: %+v", byReason)
	}

	// Newest first.
	all, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "acme", Limit: 10, IP: "", Reason: ""})
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

	got, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "acme", Limit: 3, IP: "", Reason: ""})
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

	got, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "default", Limit: 10, IP: "", Reason: ""})
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

	got, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "", Limit: 10, IP: "", Reason: ""}) // tenantID: "" -> should behave like "default"
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

// A window is what turns this store from a monitoring view into a record. The
// question an auditor asks is never "what happened lately" — it is "what
// happened between these two dates", and until LogFilter carried From/To the
// store could not answer it at all.
func TestPGSink_QueryLogs_FiltersByTimeWindow(t *testing.T) {
	s, _ := testSink(t)
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

	// Three events, one per month, inserted with explicit timestamps.
	for i, ts := range []time.Time{
		base.AddDate(0, -1, 0), // June
		base,                   // July
		base.AddDate(0, 1, 0),  // August
	} {
		s.Push(store.ForensicEntry{
			Tenant: "acme", Timestamp: ts, IP: "1.1.1.1",
			Path: "/x", Method: "GET", Reason: "waf_block", Code: 403 + i,
		})
	}
	s.Flush()

	q := func(from, to time.Time) []store.ForensicEntry {
		t.Helper()
		got, err := s.QueryLogs(context.Background(), LogFilter{
			TenantID: "acme", Limit: 50, From: from, To: to,
		})
		if err != nil {
			t.Fatalf("QueryLogs: %v", err)
		}
		return got
	}

	if got := q(time.Time{}, time.Time{}); len(got) != 3 {
		t.Fatalf("unbounded = %d entries, want 3", len(got))
	}
	// July only — both bounds inclusive.
	if got := q(base.AddDate(0, 0, -1), base.AddDate(0, 0, 1)); len(got) != 1 {
		t.Fatalf("July window = %d entries, want 1", len(got))
	}
	// Open-ended start: everything up to and including July.
	if got := q(time.Time{}, base); len(got) != 2 {
		t.Fatalf("up-to-July = %d entries, want 2", len(got))
	}
	// Open-ended end: July onward.
	if got := q(base, time.Time{}); len(got) != 2 {
		t.Fatalf("from-July = %d entries, want 2", len(got))
	}
	// A window with nothing in it returns nothing, not everything — the failure
	// mode that would quietly turn a narrow question into a broad answer.
	if got := q(base.AddDate(1, 0, 0), base.AddDate(1, 0, 1)); len(got) != 0 {
		t.Fatalf("empty window = %d entries, want 0", len(got))
	}
}

// A caller that omits the size must not be able to pull the whole table.
func TestPGSink_QueryLogs_DefaultsTheLimit(t *testing.T) {
	s, _ := testSink(t)
	for i := 0; i < defaultLogLimit+10; i++ {
		s.Push(store.ForensicEntry{
			Tenant: "acme", Timestamp: time.Now().UTC(), IP: "1.1.1.1",
			Path: "/x", Method: "GET", Reason: "waf_block", Code: 403,
		})
	}
	s.Flush()

	got, err := s.QueryLogs(context.Background(), LogFilter{TenantID: "acme"})
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if len(got) != defaultLogLimit {
		t.Fatalf("unbounded query returned %d entries, want the %d default", len(got), defaultLogLimit)
	}
}

// CountByReason exists so a compliance report can state how often something
// happened over a period. The report used to tally a page of recent entries
// instead, which answers "how many fit in the buffer", not "how many occurred".
func TestPGSink_CountByReason(t *testing.T) {
	s, _ := testSink(t)
	june := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	august := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	push := func(tenant, reason string, ts time.Time) {
		s.Push(store.ForensicEntry{
			Tenant: tenant, Timestamp: ts, IP: "1.1.1.1",
			Path: "/orders/42", Method: "GET", Reason: reason, Code: 200,
		})
	}
	push("acme", "bola_enumeration", june)
	push("acme", "bola_enumeration", august)
	push("acme", "bola_enumeration", august)
	push("acme", "waf_blocked", august)
	push("globex", "bola_enumeration", august) // another tenant must not leak in
	s.Flush()

	count := func(f LogFilter) map[string]int {
		t.Helper()
		got, err := s.CountByReason(context.Background(), f)
		if err != nil {
			t.Fatalf("CountByReason: %v", err)
		}
		return got
	}

	all := count(LogFilter{TenantID: "acme"})
	if all["bola_enumeration"] != 3 || all["waf_blocked"] != 1 {
		t.Fatalf("unbounded counts = %v, want 3 enumerations and 1 waf block", all)
	}

	// The window is what makes the number answer "for the period under review".
	windowed := count(LogFilter{TenantID: "acme", From: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	if windowed["bola_enumeration"] != 2 {
		t.Fatalf("windowed = %v, want 2 enumerations from July onward", windowed)
	}
	if got := count(LogFilter{TenantID: "acme", To: july(june)}); got["bola_enumeration"] != 1 {
		t.Fatalf("up-to-June = %v, want 1", got)
	}
	// A period with nothing in it counts nothing, rather than falling back to
	// everything — the failure that would quietly widen an audited window.
	if got := count(LogFilter{TenantID: "acme", From: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}); len(got) != 0 {
		t.Fatalf("empty window = %v, want no counts", got)
	}

	// Tenant scoping holds: globex's event is not in acme's totals, and acme's
	// are not in globex's.
	if g := count(LogFilter{TenantID: "globex"}); g["bola_enumeration"] != 1 {
		t.Fatalf("globex = %v, want exactly its own event", g)
	}

	// An empty tenant behaves like the default one, matching QueryLogs.
	if d := count(LogFilter{}); len(d) != 0 {
		t.Fatalf("default tenant = %v, want none (every event above belongs to a named tenant)", d)
	}
}

func july(june time.Time) time.Time { return june.AddDate(0, 0, 15) }

// Flush must persist what the worker holds privately, not merely what is still
// in the channel — the distinction that made two earlier tests flaky.
func TestPGSink_FlushPersistsTheWorkersBatch(t *testing.T) {
	s, _ := testSink(t)
	const n = 40
	for i := 0; i < n; i++ {
		s.Push(store.ForensicEntry{
			Tenant: "acme", Timestamp: time.Now().UTC(), IP: "1.1.1.1",
			Path: "/x", Method: "GET", Reason: "flush_probe", Code: 200,
		})
	}
	s.Flush()

	got, err := s.CountByReason(context.Background(), LogFilter{TenantID: "acme"})
	if err != nil {
		t.Fatalf("CountByReason: %v", err)
	}
	if got["flush_probe"] != n {
		t.Fatalf("persisted %d of %d entries: Flush returned before the worker's batch was written",
			got["flush_probe"], n)
	}
}
