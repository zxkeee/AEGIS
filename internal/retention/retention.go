// Package retention bounds the growth of AEGIS's durable PostgreSQL tables.
//
// Most state is already bounded: Redis keys carry TTLs and the forensic ring
// buffer is capped. But the durable tables grow with traffic and, left alone,
// grow without limit — forensic_logs (one row per security block), the admin
// audit log, and the consumer graph (api_consumers / api_endpoint_consumers,
// which gain a row per distinct caller / caller-endpoint pair). This worker
// deletes rows older than a configured window on a periodic sweep.
//
// The endpoint catalog (api_endpoints / api_endpoint_status) is deliberately
// NOT pruned: it is bounded by path normalisation and is the valuable inventory
// the whole product is built around.
package retention

import (
	"api-gateway/internal/audit"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"api-gateway/internal/config"

	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

// Logger is the minimal logging surface the worker needs.
type Logger interface {
	Info(msg string, fields ...map[string]any)
	Error(msg string, fields ...map[string]any)
}

// Worker runs the periodic retention sweep against the shared catalog/forensic
// database.
type Worker struct {
	db  *sql.DB
	cfg config.RetentionConfig
	log Logger
}

// Stats reports how many rows a sweep deleted, per table group.
type Stats struct {
	Forensic      int64
	Audit         int64
	Consumers     int64
	ConsumerEdges int64
}

// New opens a small dedicated connection pool on the shared DSN. The caller owns
// the returned Worker's lifecycle via Run(ctx) and must Close it.
func New(dsn string, cfg config.RetentionConfig, log Logger) (*Worker, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("retention: open: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("retention: ping: %w", err)
	}
	return &Worker{db: db, cfg: cfg, log: log}, nil
}

// Close releases the connection pool.
func (w *Worker) Close() error { return w.db.Close() }

// Run sweeps once immediately, then on every Interval tick, until ctx is done.
// It never returns an error — a failed sweep is logged and retried next tick, so
// a transient DB issue does not take the worker down.
func (w *Worker) Run(ctx context.Context) {
	w.runSweep(ctx)
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.log.Info("retention: worker stopped")
			return
		case <-ticker.C:
			w.runSweep(ctx)
		}
	}
}

func (w *Worker) runSweep(ctx context.Context) {
	start := time.Now()
	st, err := w.Sweep(ctx)
	if err != nil {
		w.log.Error("retention: sweep failed (will retry next interval)", map[string]any{"error": err.Error()})
		return
	}
	w.log.Info("retention: sweep complete", map[string]any{
		"forensic_deleted":       st.Forensic,
		"audit_deleted":          st.Audit,
		"consumers_deleted":      st.Consumers,
		"consumer_edges_deleted": st.ConsumerEdges,
		"took_ms":                time.Since(start).Milliseconds(),
	})
}

// Sweep performs one retention pass and returns the per-table delete counts. It
// is exported so it can be driven directly by tests and, potentially, an
// on-demand admin trigger.
//
// Each table group runs in its OWN transaction so a failure (or a missing table)
// on one does not roll back the others — a retention sweep is maintenance and
// should make whatever progress it can. Errors are collected and joined. The
// catalog and forensic tables enforce row-level security keyed on the
// app.tenant_id GUC; this maintenance path sets the documented '*' escape value
// so a DELETE spans every tenant (the admin audit log has no RLS and is
// unaffected). now is passed in so tests can pin the clock.
func (w *Worker) Sweep(ctx context.Context) (Stats, error) {
	return w.sweepAt(ctx, time.Now())
}

func (w *Worker) sweepAt(ctx context.Context, now time.Time) (Stats, error) {
	var st Stats
	var errs []error

	if d := w.cfg.ForensicDays; d > 0 {
		cutoff := now.AddDate(0, 0, -d)
		if err := w.inTenantTx(ctx, func(tx *sql.Tx) error {
			n, err := exec(ctx, tx, `DELETE FROM forensic_logs WHERE ts < $1`, cutoff)
			st.Forensic = n
			return err
		}); err != nil {
			errs = append(errs, fmt.Errorf("forensic_logs: %w", err))
		}
	}

	if d := w.cfg.AuditDays; d > 0 {
		cutoff := now.AddDate(0, 0, -d)
		if err := w.inTenantTx(ctx, func(tx *sql.Tx) error {
			// The audit trail is chained and its head commits to a count, so a
			// deletion nobody records reads as tampering — correctly, because
			// from the outside it is indistinguishable from one. Retention
			// therefore REPORTS what it removed, per tenant, in the same
			// transaction as the delete. An operator who deletes rows without
			// this step still fails verification, which is the point.
			n, err := w.pruneAuditPerTenant(ctx, tx, cutoff)
			st.Audit = n
			return err
		}); err != nil {
			errs = append(errs, fmt.Errorf("admin_audit_log: %w", err))
		}
	}

	if d := w.cfg.ConsumerIdleDays; d > 0 {
		cutoff := now.AddDate(0, 0, -d)
		if err := w.inTenantTx(ctx, func(tx *sql.Tx) error {
			// Prune idle per-pair edges and idle consumers, then sweep any edges
			// left orphaned (their consumer just went away). Orphan pass runs last.
			e1, err := exec(ctx, tx, `DELETE FROM api_endpoint_consumers WHERE last_seen < $1`, cutoff)
			if err != nil {
				return err
			}
			c, err := exec(ctx, tx, `DELETE FROM api_consumers WHERE last_seen < $1`, cutoff)
			if err != nil {
				return err
			}
			e2, err := exec(ctx, tx, `DELETE FROM api_endpoint_consumers e
				WHERE NOT EXISTS (
					SELECT 1 FROM api_consumers c
					WHERE c.tenant_id = e.tenant_id AND c.id = e.consumer_id)`)
			if err != nil {
				return err
			}
			st.Consumers = c
			st.ConsumerEdges = e1 + e2
			return nil
		}); err != nil {
			errs = append(errs, fmt.Errorf("consumer graph: %w", err))
		}
	}

	return st, errors.Join(errs...)
}

// inTenantTx runs fn in a transaction that spans all tenants via the RLS
// app.tenant_id='*' escape hatch, committing on success.
func (w *Worker) inTenantTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		return fmt.Errorf("set tenant GUC: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func exec(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// pruneAuditPerTenant deletes expired audit rows and tells each tenant's audit
// head what was removed.
//
// Per tenant rather than one blanket DELETE, because the head is per tenant and
// a single total would leave every tenant's count wrong. The whole thing runs
// in the caller's transaction, so a crash between the delete and the record
// cannot leave a trail that reads as tampered.
func (w *Worker) pruneAuditPerTenant(ctx context.Context, tx *sql.Tx, cutoff time.Time) (int64, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT tenant_id, count(*), COALESCE(max(id), 0)
FROM admin_audit_log WHERE ts < $1 GROUP BY tenant_id`, cutoff)
	if err != nil {
		return 0, err
	}
	type victim struct {
		tenant  string
		count   int64
		highest int64
	}
	var victims []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.tenant, &v.count, &v.highest); err != nil {
			_ = rows.Close()
			return 0, err
		}
		victims = append(victims, v)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()

	var total int64
	for _, v := range victims {
		n, err := exec(ctx, tx, `DELETE FROM admin_audit_log WHERE tenant_id = $1 AND ts < $2`,
			v.tenant, cutoff)
		if err != nil {
			return total, err
		}
		total += n
		// The signer is deliberately nil here: the retention worker does not
		// hold the report signing key, and pretending otherwise would put a
		// signing credential in a maintenance component. The head records the
		// pruning either way; an unsigned update is visible to a reader and is
		// not evidence to a third party, which is stated in the limits.
		if err := audit.RecordPruning(ctx, tx, v.tenant, v.highest, n, nil); err != nil {
			return total, err
		}
	}
	return total, nil
}
