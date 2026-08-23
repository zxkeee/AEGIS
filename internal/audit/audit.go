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
	"fmt"
	"sync"
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
}

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
	if _, err := db.ExecContext(ctx, schema); err != nil {
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
		s.log.Error("audit: buffer full, dropping entry", map[string]any{"action": e.Action, "path": e.Path})
	}
}

func (s *Store) worker() {
	defer s.wg.Done()
	for {
		select {
		case e := <-s.ch:
			s.insert(e)
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

func (s *Store) insert(e Entry) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_audit_log
		   (ts, tenant_id, actor_id, actor_email, role, super_admin, action, method, path, status, ip, detail)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.Time, e.TenantID, e.ActorID, e.ActorEmail, e.Role, e.SuperAdmin,
		e.Action, e.Method, e.Path, e.Status, e.IP, e.Detail)
	if err != nil {
		s.log.Error("audit: insert failed", map[string]any{"error": err.Error(), "action": e.Action})
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

	rows, err := s.db.QueryContext(ctx, q, args...)
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
