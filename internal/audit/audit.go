// Package audit records a persistent, queryable trail of administrative actions
// on the control plane — who did what, when, from where, and with what result.
// This is an enterprise/compliance table-stake (SOC 2, ISO 27001, PCI-DSS
// "track and monitor all access"): the application log is not enough because it
// is neither tenant-scoped nor durable nor exportable.
//
// Writes are asynchronous and best-effort so the admin request path is never
// blocked by the audit backend; admin mutation volume is low (human operators),
// so a generous buffer makes drops practically impossible. Reads are tenant
// -scoped (a super-admin may span tenants).
package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Logger is the minimal logging interface the store needs.
type Logger interface {
	Info(msg string, fields ...map[string]any)
	Error(msg string, fields ...map[string]any)
}

// Entry is one recorded administrative event.
type Entry struct {
	Time       time.Time `json:"time"`
	TenantID   string    `json:"tenant_id"`
	ActorID    string    `json:"actor_id,omitempty"`
	ActorEmail string    `json:"actor_email,omitempty"`
	Role       string    `json:"role,omitempty"`
	SuperAdmin bool      `json:"super_admin,omitempty"`
	// Action is a stable verb: "login", "login_failed", "logout", "mutation",
	// or "denied:<reason>" for an access-control rejection.
	Action string `json:"action"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Status int    `json:"status,omitempty"`
	IP     string `json:"ip,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Recorder is the write side, depended on by the AdminAuth middleware. A nil
// Recorder is a valid no-op (audit disabled when no database is configured).
type Recorder interface {
	Record(Entry)
}

// Filter parameterises a List query.
type Filter struct {
	TenantID string // "" or "*" with super-admin spans all tenants
	Action   string
	Limit    int
}

const schema = `
CREATE TABLE IF NOT EXISTS admin_audit_log (
	id          BIGSERIAL PRIMARY KEY,
	ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	tenant_id   TEXT    NOT NULL DEFAULT 'default',
	actor_id    TEXT    NOT NULL DEFAULT '',
	actor_email TEXT    NOT NULL DEFAULT '',
	role        TEXT    NOT NULL DEFAULT '',
	super_admin BOOLEAN NOT NULL DEFAULT FALSE,
	action      TEXT    NOT NULL,
	method      TEXT    NOT NULL DEFAULT '',
	path        TEXT    NOT NULL DEFAULT '',
	status      INT     NOT NULL DEFAULT 0,
	ip          TEXT    NOT NULL DEFAULT '',
	detail      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON admin_audit_log (tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON admin_audit_log (tenant_id, action);
`

// Store is the PostgreSQL-backed audit sink with an async writer.
type Store struct {
	db  *sql.DB
	log Logger
	ch  chan Entry

	wg   sync.WaitGroup
	quit chan struct{}
	// dropped counts entries discarded because the buffer was full, reported
	// periodically by worker. See Record.
	dropped atomic.Int64
	// signer signs the integrity head. nil when no report signing key is
	// configured, in which case the head still commits to the trail for a
	// reader and stops being evidence against the operator holding the
	// database. See integrity.go.
	signer Signer
}

// WithSigner attaches the key that signs the audit head.
//
// Separate from New so a deployment without a signing key behaves exactly as it
// did before integrity existed.
func (s *Store) WithSigner(sg Signer) *Store {
	s.signer = sg
	return s
}

// dropReportInterval is how often the worker reports accumulated drops.
const dropReportInterval = 3 * time.Second

// New connects, migrates, and starts the background writer. It reuses the same
// PostgreSQL instance as the forensic/catalog stores (forensic_dsn).
func New(dsn string, log Logger) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: pg connect: %w", err)
	}
	db.SetMaxOpenConns(3)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: pg ping: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema+integritySchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: pg migrate: %w", err)
	}

	s := &Store{
		db:   db,
		log:  log,
		ch:   make(chan Entry, 4096),
		quit: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.worker()
	return s, nil
}

// Record enqueues an entry. Non-blocking: drops on a full buffer (logged) so the
// admin path is never stalled. Defaults the tenant and timestamp.
func (s *Store) Record(e Entry) {
	if s == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.TenantID == "" {
		e.TenantID = "default"
	}
	select {
	case s.ch <- e:
	default:
		// Counted, not logged per entry: the buffer fills during a burst, so a
		// line per dropped entry answers a flood of events with a flood of logs.
		// The worker reports the total periodically instead.
		s.dropped.Add(1)
	}
}

// Dropped reports how many entries have been discarded for lack of buffer space
// since the store started.
func (s *Store) Dropped() int64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

func (s *Store) worker() {
	defer s.wg.Done()
	ticker := time.NewTicker(dropReportInterval)
	defer ticker.Stop()
	for {
		select {
		case e := <-s.ch:
			s.insert(e)
		case <-ticker.C:
			if n := s.dropped.Swap(0); n > 0 {
				s.log.Error("audit: buffer full, entries dropped — the admin action trail is incomplete",
					map[string]any{"dropped": n, "buffer_size": cap(s.ch)})
			}
		case <-s.quit:
			for {
				select {
				case e := <-s.ch:
					s.insert(e)
				default:
					return
				}
			}
		}
	}
}

// insert writes one entry, its chain link and the head, in ONE transaction.
//
// A transaction rather than a pooled Exec for two reasons, and both are
// load-bearing. app.tenant_id is transaction-scoped, so a write on the pool has
// no tenant pinned and under a role that cannot bypass RLS matches zero rows
// while reporting success — the exact trap invariant 9 exists to catch. And a
// row whose chain link or head update could fail separately would produce the
// state this mechanism is meant to detect, by accident.
func (s *Store) insert(e Entry) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.log.Error("audit: begin failed", map[string]any{"error": err.Error(), "action": e.Action})
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('app.tenant_id', $1, true)`, tenantOr(e.TenantID)); err != nil {
		s.log.Error("audit: tenant scope failed", map[string]any{"error": err.Error()})
		return
	}

	var id int64
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO admin_audit_log
		   (ts, tenant_id, actor_id, actor_email, role, super_admin, action, method, path, status, ip, detail, chain)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'')
		 RETURNING id`,
		e.Time, tenantOr(e.TenantID), e.ActorID, e.ActorEmail, e.Role, e.SuperAdmin,
		e.Action, e.Method, e.Path, e.Status, e.IP, e.Detail).Scan(&id); err != nil {
		s.log.Error("audit: insert failed", map[string]any{"error": err.Error(), "action": e.Action})
		return
	}

	// The previous link for this tenant, excluding the row just written.
	var prev string
	if err := tx.QueryRowContext(ctx,
		`SELECT chain FROM admin_audit_log WHERE tenant_id = $1 AND id < $2 ORDER BY id DESC LIMIT 1`,
		tenantOr(e.TenantID), id).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.log.Error("audit: chain read failed", map[string]any{"error": err.Error()})
		return
	}

	// The chain covers the id, which the database assigns, so it is a second
	// statement rather than a guess in the first.
	digest := entryDigest(id, e)
	chain := chainValue(prev, digest, id)
	if _, err := tx.ExecContext(ctx,
		`UPDATE admin_audit_log SET digest = $3, chain = $4 WHERE tenant_id = $1 AND id = $2`,
		tenantOr(e.TenantID), id, digest, chain); err != nil {
		s.log.Error("audit: chain write failed", map[string]any{"error": err.Error()})
		return
	}
	if err := advanceHead(ctx, tx, e.TenantID, id, chain, s.signer); err != nil {
		s.log.Error("audit: head update failed", map[string]any{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		s.log.Error("audit: commit failed", map[string]any{"error": err.Error(), "action": e.Action})
	}
}

// List returns recent entries for the filter's tenant, newest first. A super
// -admin caller (TenantID "*") spans all tenants.
func (s *Store) List(ctx context.Context, f Filter) ([]Entry, error) {
	q := `SELECT ts, tenant_id, actor_id, actor_email, role, super_admin,
		action, method, path, status, ip, detail FROM admin_audit_log`
	var args []any
	where := ""
	if f.TenantID != "*" {
		where = " WHERE tenant_id = $1"
		args = append(args, tenantOr(f.TenantID))
	}
	q += where
	if f.Action != "" {
		if where == "" {
			q += fmt.Sprintf(" WHERE action = $%d", len(args)+1)
		} else {
			q += fmt.Sprintf(" AND action = $%d", len(args)+1)
		}
		args = append(args, f.Action)
	}
	q += " ORDER BY ts DESC"
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q += fmt.Sprintf(" LIMIT $%d", len(args)+1) // #nosec G202 -- parameterized; only $N placeholders concatenated
	args = append(args, limit)

	// A read-only transaction with the tenant pinned, because the table now
	// carries row-level security. On a pooled handle the GUC is unset, the
	// policy matches nothing, and the listing comes back empty while reporting
	// success — the same shape that made a discovery test assert about rows it
	// had never written (handoff §0c, item 5). The application-level WHERE
	// stays: RLS is the backstop, not the filter.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	scope := tenantOr(f.TenantID)
	if f.TenantID == "*" {
		scope = "*" // super-admin listing; the policy's documented escape hatch
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, scope); err != nil {
		return nil, err
	}

	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Time, &e.TenantID, &e.ActorID, &e.ActorEmail, &e.Role,
			&e.SuperAdmin, &e.Action, &e.Method, &e.Path, &e.Status, &e.IP, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Close drains the buffer and shuts down.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	close(s.quit)
	s.wg.Wait()
	return s.db.Close()
}

func tenantOr(t string) string {
	if t == "" {
		return "default"
	}
	return t
}
