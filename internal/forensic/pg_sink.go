package forensic

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"api-gateway/internal/store"

	_ "github.com/lib/pq" // PostgreSQL driver
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
}

const createTableSQL = `
CREATE TABLE IF NOT EXISTS forensic_logs (
	id         BIGSERIAL PRIMARY KEY,
	ts         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	ip         TEXT NOT NULL,
	path       TEXT NOT NULL,
	method     TEXT NOT NULL,
	reason     TEXT NOT NULL,
	code       INT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_forensic_ts ON forensic_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_forensic_ip ON forensic_logs (ip);
CREATE INDEX IF NOT EXISTS idx_forensic_reason ON forensic_logs (reason);
`

// NewPGSink creates a new PostgreSQL forensic log sink.
// It creates the table if it doesn't exist and starts a background flush worker.
func NewPGSink(dsn string, log Logger) (*PGSink, error) {
	db, err := sql.Open("postgres", dsn)
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
		db.Close()
		return nil, fmt.Errorf("forensic: pg ping: %w", err)
	}

	// Auto-create table and indices
	if _, err := db.ExecContext(ctx, createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("forensic: pg migrate: %w", err)
	}

	s := &PGSink{
		db:   db,
		log:  log,
		ch:   make(chan store.ForensicEntry, 4096), // buffer up to 4096 events
		quit: make(chan struct{}),
	}

	s.wg.Add(1)
	go s.flushWorker()

	return s, nil
}

// Push enqueues a forensic entry for async persistence.
// Non-blocking: drops events if the buffer is full (back-pressure).
func (s *PGSink) Push(e store.ForensicEntry) {
	select {
	case s.ch <- e:
	default:
		// Buffer full — drop event to avoid blocking the request path.
		// Redis still has the event, so no data is truly lost.
	}
}

// Close drains the buffer and shuts down the sink.
func (s *PGSink) Close() {
	close(s.quit)
	s.wg.Wait()

	// Final drain
	s.flush(s.drain())

	s.db.Close()
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
		case <-ticker.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = batch[:0]
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
	sb.WriteString("INSERT INTO forensic_logs (ts, ip, path, method, reason, code) VALUES ")

	args := make([]any, 0, len(batch)*6)
	for i, e := range batch {
		if i > 0 {
			sb.WriteString(",")
		}
		n := i * 6
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4, n+5, n+6)
		args = append(args, e.Timestamp, e.IP, e.Path, e.Method, e.Reason, e.Code)
	}

	if _, err := s.db.ExecContext(ctx, sb.String(), args...); err != nil {
		s.log.Error("forensic: pg flush failed", map[string]any{
			"error": err.Error(),
			"count": len(batch),
		})
		return
	}

	s.log.Info("forensic: flushed to postgresql", map[string]any{"count": len(batch)})
}

// QueryLogs retrieves forensic logs from PostgreSQL with optional filters.
func (s *PGSink) QueryLogs(ctx context.Context, limit int, ip, reason string) ([]store.ForensicEntry, error) {
	var sb strings.Builder
	sb.WriteString("SELECT ts, ip, path, method, reason, code FROM forensic_logs WHERE 1=1")

	args := make([]any, 0, 3)
	n := 1

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

	sb.WriteString(" ORDER BY ts DESC")
	fmt.Fprintf(&sb, " LIMIT $%d", n)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []store.ForensicEntry
	for rows.Next() {
		var e store.ForensicEntry
		if err := rows.Scan(&e.Timestamp, &e.IP, &e.Path, &e.Method, &e.Reason, &e.Code); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	return entries, rows.Err()
}
