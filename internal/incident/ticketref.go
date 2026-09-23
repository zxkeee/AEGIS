package incident

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Ticket bookkeeping: which incidents have been filed in an external tracker.
//
// This lives in its OWN table rather than as a column on `incidents`, and the
// reason is not tidiness. `incidents` is the evidence the signed compliance
// report is computed from, and every one of its fields is covered by the
// integrity ledger's digest (ledger.go). Adding a column would mean either
// leaving it outside the digest — a field of the evidence table that nothing
// commits to — or including it, which would change the digest of every incident
// that already exists and make a routine upgrade look exactly like tampering:
// every row reported as altered, on a mechanism whose entire value is that the
// report means something.
//
// A pointer to a Jira issue is also not evidence about what happened. It is
// bookkeeping about a different system, and it belongs beside the register
// rather than inside it.

const ticketSchema = `
CREATE TABLE IF NOT EXISTS incident_tickets (
	tenant_id   TEXT        NOT NULL DEFAULT 'default',
	incident_id TEXT        NOT NULL,
	system      TEXT        NOT NULL,
	ref         TEXT        NOT NULL,
	url         TEXT        NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (tenant_id, incident_id)
);

ALTER TABLE incident_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_tickets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_tickets;
CREATE POLICY tenant_isolation ON incident_tickets
	USING (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*')
	WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*');
`

// Ticket is one incident's record in an external tracker.
type Ticket struct {
	IncidentID string    `json:"incident_id"`
	System     string    `json:"system"`
	Ref        string    `json:"ref"`
	URL        string    `json:"url,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Fileable is an incident that should have a ticket and does not.
type Fileable struct {
	ID       string
	Title    string
	Class    string
	Subject  string
	Severity Severity
	Detected time.Time
	Events   int
}

// ErrTicketExists reports that this incident already has a ticket.
//
// A distinct error rather than a silent success: the caller has just made an
// HTTP request to create something, and "it was already there" is the outcome
// it most needs to be able to notice.
var ErrTicketExists = errors.New("incident: ticket already recorded")

// Unticketed returns incidents at or above minSeverity that have no ticket.
//
// Ordered oldest first: a backlog drains in the order things happened, so a
// burst does not leave the earliest incident waiting behind everything that
// came after it.
func (s *PGStore) Unticketed(ctx context.Context, tenantID string, minSeverity Severity, limit int) ([]Fileable, error) {
	if limit <= 0 {
		limit = 50
	}
	var out []Fileable
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
SELECT i.id, i.title, i.class, i.subject, i.severity, i.detected_at, i.event_count
FROM incidents i
LEFT JOIN incident_tickets t
       ON t.tenant_id = i.tenant_id AND t.incident_id = i.id
WHERE i.tenant_id = $1
  AND t.incident_id IS NULL
  -- Severity ordering lives in one place: the ARRAY literal below, whose order
  -- matches the Severity constants. Comparing the strings would order them
  -- alphabetically, which puts "major" below "minor" and files the wrong half
  -- of the register.
  AND array_position(ARRAY['minor','significant','major'], i.severity)
      >= array_position(ARRAY['minor','significant','major'], $2::text)
ORDER BY i.detected_at
LIMIT $3`, tenantOr(tenantID), string(minSeverity), limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var f Fileable
			if err := rows.Scan(&f.ID, &f.Title, &f.Class, &f.Subject,
				&f.Severity, &f.Detected, &f.Events); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// RecordTicket stores the reference to an externally created ticket.
//
// Returns ErrTicketExists rather than overwriting. Two gateways filing the same
// incident concurrently is an ordinary race — both find it unticketed, both
// create — and the loser must learn that it did, so the duplicate it just
// created can be reported rather than silently forgotten.
func (s *PGStore) RecordTicket(ctx context.Context, tenantID, incidentID, system, ref, url string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT INTO incident_tickets (tenant_id, incident_id, system, ref, url)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, incident_id) DO NOTHING`,
			tenantOr(tenantID), incidentID, system, ref, url)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrTicketExists
		}
		return nil
	})
}

// TicketFor returns the ticket recorded for one incident, or nil.
func (s *PGStore) TicketFor(ctx context.Context, tenantID, incidentID string) (*Ticket, error) {
	var t *Ticket
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var got Ticket
		err := tx.QueryRowContext(ctx, `
SELECT incident_id, system, ref, url, created_at
FROM incident_tickets WHERE tenant_id = $1 AND incident_id = $2`,
			tenantOr(tenantID), incidentID).Scan(
			&got.IncidentID, &got.System, &got.Ref, &got.URL, &got.CreatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		t = &got
		return nil
	})
	return t, err
}

// TenantsWithIncidents lists every tenant holding an incident.
//
// Uses the `*` escape hatch the RLS policies define for maintenance work, in a
// read-only transaction, because a sweep across tenants is exactly the case
// that escape hatch exists for — the retention sweep does the same. Scoping it
// to one tenant would mean the worker could never discover a tenant it had not
// been told about.
func (s *PGStore) TenantsWithIncidents(ctx context.Context) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM incidents ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
