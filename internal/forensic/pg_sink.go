package forensic

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"api-gateway/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

// Logger is a minimal logging interface.
type Logger interface {
	Info(msg string, fields ...map[string]any)
	Error(msg string, fields ...map[string]any)
}

// PGSink writes forensic log entries to PostgreSQL in buffered batches.
type PGSink struct {
	db   *sql.DB
	log  Logger
	ch   chan store.ForensicEntry
	wg   sync.WaitGroup
	quit chan struct{}
	// flushReq asks the worker to persist what it holds. It carries a channel
	// the worker closes when done, so Flush can wait for the write rather than
	// for a timer.
	flushReq chan chan struct{}
	// dropped counts entries discarded because the buffer was full, reported by
	// flushWorker. See Push.
	dropped atomic.Int64
}

const createTableSQL = `
CREATE TABLE IF NOT EXISTS forensic_logs (
	id         BIGSERIAL PRIMARY KEY,
	tenant_id  TEXT NOT NULL DEFAULT 'default',
	ts         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	ip         TEXT NOT NULL,
	path       TEXT NOT NULL,
	method     TEXT NOT NULL,
	reason     TEXT NOT NULL,
	code       INT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Idempotent migration for installs created before multi-tenancy.
ALTER TABLE forensic_logs ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
-- Tenant-leading indexes so reads are always scoped efficiently.
CREATE INDEX IF NOT EXISTS idx_forensic_ts ON forensic_logs (tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_forensic_ip ON forensic_logs (tenant_id, ip);
CREATE INDEX IF NOT EXISTS idx_forensic_reason ON forensic_logs (tenant_id, reason);

-- Row-Level Security (ADR-001 phase 2b). Same fail-closed backstop as the
-- catalog tables: a SELECT/INSERT without app.tenant_id sees nothing.
-- Use '*' from withinTenantTx-style helpers (PGSink.flush groups by tenant).
ALTER TABLE forensic_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON forensic_logs;
CREATE POLICY tenant_isolation ON forensic_logs
  USING (tenant_id = current_setting('app.tenant_id', true)
      OR current_setting('app.tenant_id', true) = '*')
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
      OR current_setting('app.tenant_id', true) = '*');
`

// NewPGSink creates a new PostgreSQL forensic log sink.
// It creates the table if it doesn't exist and starts a background flush worker.
func NewPGSink(dsn string, log Logger) (*PGSink, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("forensic: pg connect: %w", err)
	}

	// Connection pool settings for high-throughput writes
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("forensic: pg ping: %w", err)
	}

	// Auto-create table and indices
	if _, err := db.ExecContext(ctx, createTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("forensic: pg migrate: %w", err)
	}

	s := &PGSink{
		db:       db,
		log:      log,
		ch:       make(chan store.ForensicEntry, 4096), // buffer up to 4096 events
		quit:     make(chan struct{}),
		flushReq: make(chan chan struct{}),
	}

	s.wg.Add(1)
	go s.flushWorker()

	return s, nil
}

// Push enqueues a forensic entry for async persistence. Non-blocking: an entry
// is dropped when the buffer is full, so a burst never stalls the request path.
//
// Drops are COUNTED and reported, because the buffer fills exactly when the
// forensic record matters most — a burst of blocks is an attack in progress —
// and an unreported drop leaves an operator unable to tell a complete evidence
// trail from one missing most of the incident.
//
// This used to be silent, on the stated grounds that "Redis still has the
// event, so no data is truly lost". That does not hold: the Redis ring is
// trimmed to the last 1000 entries (store.PushForensic), so the same burst that
// overflows this 4096-entry buffer also rolls the ring several times over. Both
// copies are lost together, which is the case the reasoning assumed away.
// internal/audit already logs its equivalent drop; this is the same defect,
// handled the same way.
func (s *PGSink) Push(e store.ForensicEntry) {
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

// Dropped reports how many entries have been discarded for lack of buffer space
// since the sink started. Exposed so the gap can be surfaced alongside the other
// coverage counters rather than living only in the log.
func (s *PGSink) Dropped() int64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// Flush persists everything buffered and returns once it is durable, without
// shutting the sink down. Use it as a checkpoint before reading the record back.
//
// It asks the WORKER to do the write rather than doing it directly. That
// distinction is the whole correctness of this method: the worker moves entries
// out of the channel into a batch it owns privately, so a caller that only
// drained the channel would miss everything already collected and return having
// persisted less than it claimed — exactly the kind of half-guarantee that is
// worse than no guarantee.
func (s *PGSink) Flush() {
	done := make(chan struct{})
	select {
	case s.flushReq <- done:
		<-done
	case <-s.quit:
		// Shutting down; Close performs the final flush itself.
	}
}

// Close drains the buffer and shuts down the sink.
func (s *PGSink) Close() {
	close(s.quit)
	s.wg.Wait()

	// Final drain
	s.flush(s.drain())

	_ = s.db.Close()
}

// flushWorker batches events every 3 seconds or when 500 events accumulate.
func (s *PGSink) flushWorker() {
	defer s.wg.Done()

	batch := make([]store.ForensicEntry, 0, 500)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case e := <-s.ch:
			batch = append(batch, e)
			if len(batch) >= 500 {
				s.flush(batch)
				batch = batch[:0]
			}
		case done := <-s.flushReq:
			batch = append(batch, s.drain()...)
			if len(batch) > 0 {
				s.flush(batch)
				batch = batch[:0]
			}
			close(done)
		case <-ticker.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = batch[:0]
			}
			// Report drops on the tick rather than per drop: the overflow that
			// causes them is a burst, so a line per dropped entry would answer a
			// flood of events with a flood of logs.
			if n := s.dropped.Swap(0); n > 0 {
				s.log.Error("forensic: buffer full, entries dropped — the persisted record is incomplete", map[string]any{
					"dropped":     n,
					"buffer_size": cap(s.ch),
				})
			}
		case <-s.quit:
			// Drain remaining
			batch = append(batch, s.drain()...)
			if len(batch) > 0 {
				s.flush(batch)
			}
			return
		}
	}
}

// drain collects all remaining buffered entries.
func (s *PGSink) drain() []store.ForensicEntry {
	var out []store.ForensicEntry
	for {
		select {
		case e := <-s.ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

// flush performs a batched INSERT into PostgreSQL.
func (s *PGSink) flush(batch []store.ForensicEntry) {
	if len(batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build multi-row INSERT for efficiency
	var sb strings.Builder
	sb.WriteString("INSERT INTO forensic_logs (tenant_id, ts, ip, path, method, reason, code) VALUES ")

	args := make([]any, 0, len(batch)*7)
	for i, e := range batch {
		if i > 0 {
			sb.WriteString(",")
		}
		n := i * 7
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4, n+5, n+6, n+7)
		tid := e.Tenant
		if tid == "" {
			tid = "default"
		}
		args = append(args, tid, e.Timestamp, e.IP, e.Path, e.Method, e.Reason, e.Code)
	}

	// Batched insert spans tenants; the gateway is the trusted source, so we
	// elevate the GUC to '*' for the duration of this transaction. RLS still
	// enforces that NEW rows carry a tenant_id (NOT NULL DEFAULT 'default').
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.log.Error("forensic: pg flush begin failed", map[string]any{"error": err.Error()})
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		s.log.Error("forensic: pg flush set_config failed", map[string]any{"error": err.Error()})
		return
	}
	if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
		s.log.Error("forensic: pg flush failed", map[string]any{
			"error": err.Error(),
			"count": len(batch),
		})
		return
	}
	if err := tx.Commit(); err != nil {
		s.log.Error("forensic: pg flush commit failed", map[string]any{"error": err.Error()})
		return
	}

	s.log.Info("forensic: flushed to postgresql", map[string]any{"count": len(batch)})
}

// defaultLogLimit bounds a query that did not ask for a size, so a caller
// cannot pull the whole table by omitting one field.
const defaultLogLimit = 100

// LogFilter narrows a forensic query. A zero From/To leaves that bound open.
//
// The time bounds are what make this store usable as evidence. A finding says
// "sensitive data reached unauthenticated callers"; the question that follows is
// "show me, for the period under review". Without a window the only answerable
// question is "what happened lately", which is a monitoring view, not a record.
type LogFilter struct {
	TenantID string
	Limit    int
	IP       string
	Reason   string
	From     time.Time
	To       time.Time
}

// CountByReason totals recorded events per reason over the filter's window.
//
// Separate from QueryLogs because a compliance report needs the total, not the
// rows: counting by pulling a page of entries and tallying them — which is what
// the report used to do against a capped in-memory ring — reports whatever
// happened to fit rather than what happened.
func (s *PGSink) CountByReason(ctx context.Context, f LogFilter) (map[string]int, error) {
	tenantID := f.TenantID
	if tenantID == "" {
		tenantID = "default"
	}

	var sb strings.Builder
	sb.WriteString("SELECT reason, count(*) FROM forensic_logs WHERE tenant_id = $1")
	// Placeholder numbers are derived from the argument list rather than a
	// counter kept alongside it, so the two cannot drift as clauses are added.
	args := []any{tenantID}
	if !f.From.IsZero() {
		fmt.Fprintf(&sb, " AND ts >= $%d", len(args)+1)
		args = append(args, f.From.UTC())
	}
	if !f.To.IsZero() {
		fmt.Fprintf(&sb, " AND ts <= $%d", len(args)+1)
		args = append(args, f.To.UTC())
	}
	sb.WriteString(" GROUP BY reason")

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := map[string]int{}
	for rows.Next() {
		var reason string
		var count int
		if err := rows.Scan(&reason, &count); err != nil {
			return nil, err
		}
		out[reason] = count
	}
	return out, rows.Err()
}

// QueryLogs retrieves forensic logs from PostgreSQL, newest first.
func (s *PGSink) QueryLogs(ctx context.Context, f LogFilter) ([]store.ForensicEntry, error) {
	tenantID := f.TenantID
	if tenantID == "" {
		tenantID = "default"
	}
	limit, ip, reason := f.Limit, f.IP, f.Reason
	if limit <= 0 {
		limit = defaultLogLimit
	}
	var sb strings.Builder
	sb.WriteString("SELECT tenant_id, ts, ip, path, method, reason, code FROM forensic_logs WHERE tenant_id = $1")

	args := []any{tenantID}
	n := 2

	if ip != "" {
		fmt.Fprintf(&sb, " AND ip = $%d", n)
		args = append(args, ip)
		n++
	}
	if reason != "" {
		fmt.Fprintf(&sb, " AND reason = $%d", n)
		args = append(args, reason)
		n++
	}
	if !f.From.IsZero() {
		fmt.Fprintf(&sb, " AND ts >= $%d", n)
		args = append(args, f.From.UTC())
		n++
	}
	if !f.To.IsZero() {
		fmt.Fprintf(&sb, " AND ts <= $%d", n)
		args = append(args, f.To.UTC())
		n++
	}

	sb.WriteString(" ORDER BY ts DESC")
	fmt.Fprintf(&sb, " LIMIT $%d", n)
	args = append(args, limit)

	// Reads are scoped to a single tenant by the explicit WHERE above; we also
	// pin app.tenant_id so RLS gives the same answer if WHERE is ever dropped.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []store.ForensicEntry
	for rows.Next() {
		var e store.ForensicEntry
		if err := rows.Scan(&e.Tenant, &e.Timestamp, &e.IP, &e.Path, &e.Method, &e.Reason, &e.Code); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, tx.Commit()
}
