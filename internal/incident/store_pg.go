package incident

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver
)

// incidentSchema creates the table. Tenant-scoped and RLS-protected on exactly
// the pattern the catalog and forensic tables use (ADR-001) — an incident names
// who attacked which endpoints, so a leak across tenants would be worse here
// than almost anywhere else in the system.
const incidentSchema = `
CREATE TABLE IF NOT EXISTS incidents (
	tenant_id           TEXT NOT NULL DEFAULT 'default',
	id                  TEXT NOT NULL,
	title               TEXT NOT NULL,
	class               TEXT NOT NULL,
	subject             TEXT NOT NULL,
	status              TEXT NOT NULL DEFAULT 'open',
	severity            TEXT NOT NULL DEFAULT 'minor',
	severity_confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
	detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_event_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	closed_at           TIMESTAMPTZ,
	event_count         BIGINT NOT NULL DEFAULT 0,
	endpoints           TEXT[] NOT NULL DEFAULT '{}',
	sources             TEXT[] NOT NULL DEFAULT '{}',
	reasons             TEXT[] NOT NULL DEFAULT '{}',
	clients_affected    INT,
	geographic_spread   TEXT,
	economic_impact_eur DOUBLE PRECISION,
	notes               TEXT NOT NULL DEFAULT '',
	notifications       JSONB NOT NULL DEFAULT '[]'::jsonb,
	PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_detected ON incidents (tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents (tenant_id, status);
-- The correlation lookup: the open incident for one key, most recent first.
CREATE INDEX IF NOT EXISTS idx_incidents_key      ON incidents (tenant_id, class, subject, last_event_at DESC);

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incidents;
CREATE POLICY tenant_isolation ON incidents
	USING (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*')
	WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*');
`

// pgTypeMap adapts pgx's array codecs to database/sql's Scanner interface, the
// same way the catalog does it: pgx binds a plain []string as text[] natively
// on the way in, but scanning an array column back needs this adapter. Built
// once; safe for concurrent use.
var pgTypeMap = pgtype.NewMap()

// PGStore persists incidents in PostgreSQL.
type PGStore struct {
	db  *sql.DB
	log Logger
}

// NewPGStore opens the store against an existing pool and applies the schema.
func NewPGStore(db *sql.DB, log Logger) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("incident: nil database handle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, incidentSchema); err != nil {
		return nil, fmt.Errorf("incident: schema: %w", err)
	}
	return &PGStore{db: db, log: log}, nil
}

// arr binds a nil slice as an empty array rather than NULL. The columns are
// NOT NULL, and a delta with no endpoints is perfectly ordinary.
func arr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func tenantOr(t string) string {
	if t == "" {
		return "default"
	}
	return t
}

// withTenantTx pins app.tenant_id for the transaction so RLS applies to every
// statement inside it. Same contract as discovery's: a forgotten WHERE clause
// becomes a no-op rather than a cross-tenant read.
func (s *PGStore) withTenantTx(ctx context.Context, tenantID string, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantOr(tenantID)); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Merge folds a delta into the open incident for its key, or opens a new one.
//
// "Open" here means status <> 'closed' AND the last event is within window. A
// closed incident is never reopened: it may already have been reported, and
// silently appending new activity to a filed report is the one thing an
// incident record must not do.
func (s *PGStore) Merge(ctx context.Context, d Delta, window time.Duration) error {
	return s.withTenantTx(ctx, d.Tenant, func(tx *sql.Tx) error {
		var id string
		err := tx.QueryRowContext(ctx, `
SELECT id FROM incidents
WHERE tenant_id = $1 AND class = $2 AND subject = $3
  AND status <> 'closed' AND last_event_at >= $4
ORDER BY last_event_at DESC LIMIT 1`,
			tenantOr(d.Tenant), d.Class, d.Subject, d.Last.Add(-window)).Scan(&id)

		switch {
		case errors.Is(err, sql.ErrNoRows):
			return s.insert(ctx, tx, d)
		case err != nil:
			return err
		default:
			return s.update(ctx, tx, id, d)
		}
	})
}

func (s *PGStore) insert(ctx context.Context, tx *sql.Tx, d Delta) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO incidents
	(tenant_id, id, title, class, subject, status, severity, detected_at,
	 last_event_at, event_count, endpoints, sources, reasons)
VALUES ($1,$2,$3,$4,$5,'open','minor',$6,$7,$8,$9,$10,$11)`,
		tenantOr(d.Tenant), newID(d), Title(d.Class, d.Subject), d.Class, d.Subject,
		d.First, d.Last, d.Count,
		arr(d.Endpoints), arr(d.Sources), arr(d.Reasons))
	return err
}

func (s *PGStore) update(ctx context.Context, tx *sql.Tx, id string, d Delta) error {
	// The array columns are unioned and re-capped in SQL so two gateways
	// merging concurrently cannot lose each other's values, and so an attacker
	// rotating source addresses cannot grow a row without bound.
	_, err := tx.ExecContext(ctx, `
UPDATE incidents SET
	last_event_at = GREATEST(last_event_at, $3),
	detected_at   = LEAST(detected_at, $4),
	event_count   = event_count + $5,
	endpoints     = (SELECT ARRAY(SELECT DISTINCT unnest(endpoints || $6::text[]) ORDER BY 1 LIMIT 50)),
	sources       = (SELECT ARRAY(SELECT DISTINCT unnest(sources   || $7::text[]) ORDER BY 1 LIMIT 50)),
	reasons       = (SELECT ARRAY(SELECT DISTINCT unnest(reasons   || $8::text[]) ORDER BY 1 LIMIT 50))
WHERE tenant_id = $1 AND id = $2`,
		tenantOr(d.Tenant), id, d.Last, d.First, d.Count,
		arr(d.Endpoints), arr(d.Sources), arr(d.Reasons))
	return err
}

// newID is deterministic in the incident's identity and its start, so a retried
// merge cannot produce two incidents for the same activity.
func newID(d Delta) string {
	return fmt.Sprintf("%s:%s:%d", d.Class, sanitiseID(d.Subject), d.First.UTC().Unix())
}

func sanitiseID(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// Filter selects incidents for a listing.
type Filter struct {
	Status   string
	Severity string
	Class    string
	From, To time.Time
	Limit    int
	// OverdueOnly keeps only incidents with an unmet obligation. Applied in Go
	// rather than SQL because a deadline depends on the notification history
	// and the schedule, which are not columns.
	OverdueOnly bool
}

const defaultLimit = 100

// List returns incidents for a tenant, newest first.
func (s *PGStore) List(ctx context.Context, tenant string, f Filter, sched Schedule, now time.Time) ([]Incident, error) {
	q := strings.Builder{}
	q.WriteString(`
SELECT id, title, class, subject, status, severity, severity_confirmed,
       detected_at, last_event_at, closed_at, event_count, endpoints, sources,
       reasons, clients_affected, geographic_spread, economic_impact_eur, notes,
       notifications
FROM incidents WHERE tenant_id = $1`)
	args := []any{tenantOr(tenant)}

	add := func(clause string, v any) {
		args = append(args, v)
		fmt.Fprintf(&q, " AND %s $%d", clause, len(args))
	}
	if f.Status != "" {
		add("status =", f.Status)
	}
	if f.Severity != "" {
		add("severity =", f.Severity)
	}
	if f.Class != "" {
		add("class =", f.Class)
	}
	if !f.From.IsZero() {
		add("last_event_at >=", f.From)
	}
	if !f.To.IsZero() {
		add("detected_at <=", f.To)
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = defaultLimit
	}
	args = append(args, limit)
	fmt.Fprintf(&q, " ORDER BY detected_at DESC LIMIT $%d", len(args))

	var out []Incident
	err := s.withTenantTx(ctx, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, q.String(), args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			inc, err := scanIncident(rows)
			if err != nil {
				return err
			}
			inc.Tenant = tenantOr(tenant)
			if f.OverdueOnly && !inc.Overdue(sched, now) {
				continue
			}
			out = append(out, inc)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one incident, or nil when it does not exist for this tenant.
func (s *PGStore) Get(ctx context.Context, tenant, id string) (*Incident, error) {
	var inc *Incident
	err := s.withTenantTx(ctx, tenant, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
SELECT id, title, class, subject, status, severity, severity_confirmed,
       detected_at, last_event_at, closed_at, event_count, endpoints, sources,
       reasons, clients_affected, geographic_spread, economic_impact_eur, notes,
       notifications
FROM incidents WHERE tenant_id = $1 AND id = $2`, tenantOr(tenant), id)
		got, err := scanIncident(row)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		got.Tenant = tenantOr(tenant)
		inc = &got
		return nil
	})
	return inc, err
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func scanIncident(sc scanner) (Incident, error) {
	var (
		inc      Incident
		closedAt sql.NullTime
		clients  sql.NullInt64
		geo      sql.NullString
		economic sql.NullFloat64
		notifRaw []byte
	)
	err := sc.Scan(&inc.ID, &inc.Title, &inc.Class, &inc.Subject, &inc.Status,
		&inc.Severity, &inc.SeverityConfirmed, &inc.DetectedAt, &inc.LastEventAt,
		&closedAt, &inc.EventCount, pgTypeMap.SQLScanner(&inc.Endpoints), pgTypeMap.SQLScanner(&inc.Sources),
		pgTypeMap.SQLScanner(&inc.Reasons), &clients, &geo, &economic, &inc.Classification.Notes,
		&notifRaw)
	if err != nil {
		return Incident{}, err
	}
	if closedAt.Valid {
		t := closedAt.Time
		inc.ClosedAt = &t
	}
	if clients.Valid {
		v := int(clients.Int64)
		inc.Classification.ClientsAffected = &v
	}
	if geo.Valid {
		v := geo.String
		inc.Classification.GeographicSpread = &v
	}
	if economic.Valid {
		v := economic.Float64
		inc.Classification.EconomicImpactEUR = &v
	}
	if len(notifRaw) > 0 {
		if err := json.Unmarshal(notifRaw, &inc.Notifications); err != nil {
			return Incident{}, fmt.Errorf("incident %s: decode notifications: %w", inc.ID, err)
		}
	}
	inc.Classification.DurationMinutes = int(inc.LastEventAt.Sub(inc.DetectedAt).Minutes())
	inc.Classification.EndpointsAffected = len(inc.Endpoints)
	inc.Classification.SourceCount = len(inc.Sources)
	return inc, nil
}

// Update is a partial change to an incident's operator-owned fields. A nil
// pointer means "leave alone"; there is no way to express "set to zero" by
// accident.
type Update struct {
	Status            *Status
	Severity          *Severity
	ClientsAffected   *int
	GeographicSpread  *string
	EconomicImpactEUR *float64
	Notes             *string
}

// ErrNotFound is returned when the incident does not exist for the tenant.
var ErrNotFound = errors.New("incident: not found")

// ErrInvalid marks a caller mistake, as opposed to a store failure. The two
// used to be indistinguishable at the API boundary, so a database outage was
// reported to the client as a 400 with the raw driver error attached.
var ErrInvalid = errors.New("incident: invalid request")

// Apply writes an operator's changes.
//
// One static statement rather than a SET clause assembled from the fields that
// happen to be present. Building the SQL would mean concatenation (which gosec
// flags, correctly, as a class even when this instance is safe) and placeholder
// arithmetic — the exact bug that shipped twice in this codebase, once as a
// LIMIT addressed by a timestamp. COALESCE gives the same "nil means leave
// alone" semantics with nothing to get wrong.
//
// Setting a severity marks it confirmed: from then on a report can say a human
// assessed this, rather than that this package proposed it. Closing stamps
// closed_at once and does not move it on a second close — the first close is
// when it happened.
func (s *PGStore) Apply(ctx context.Context, tenant, id string, u Update) error {
	if u.Status != nil && !u.Status.Valid() {
		return fmt.Errorf("incident: unknown status %q", *u.Status)
	}
	if u.Severity != nil && !u.Severity.Valid() {
		return fmt.Errorf("incident: unknown severity %q", *u.Severity)
	}
	if u.Status == nil && u.Severity == nil && u.ClientsAffected == nil &&
		u.GeographicSpread == nil && u.EconomicImpactEUR == nil && u.Notes == nil {
		return nil
	}

	const q = `
UPDATE incidents SET
	status              = COALESCE($3::text, status),
	severity            = COALESCE($4::text, severity),
	severity_confirmed  = CASE WHEN $4::text IS NULL THEN severity_confirmed ELSE TRUE END,
	closed_at           = CASE WHEN $3::text = 'closed' THEN COALESCE(closed_at, NOW()) ELSE closed_at END,
	clients_affected    = COALESCE($5::int, clients_affected),
	geographic_spread   = COALESCE($6::text, geographic_spread),
	economic_impact_eur = COALESCE($7::double precision, economic_impact_eur),
	notes               = COALESCE($8::text, notes)
WHERE tenant_id = $1 AND id = $2`

	var status, severity any
	if u.Status != nil {
		status = string(*u.Status)
	}
	if u.Severity != nil {
		severity = string(*u.Severity)
	}

	return s.withTenantTx(ctx, tenant, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, q, tenantOr(tenant), id, status, severity,
			nullable(u.ClientsAffected), nullable(u.GeographicSpread),
			nullable(u.EconomicImpactEUR), nullable(u.Notes))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// nullable turns a nil pointer into a SQL NULL and a set one into its value, so
// COALESCE can tell "leave alone" from "set to zero". A typed nil pointer bound
// directly would work for some drivers and not others; this is unambiguous.
func nullable[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// RecordNotification appends a submitted report to the incident's history.
//
// Append-only, and now witnessed. The previous version accepted whatever
// sent_at the caller supplied and recorded nothing about when it was told, so
// "append-only" stopped a submission time being EDITED while leaving it
// perfectly possible to append a backdated one — the same outcome by another
// route. RecordedAt is stamped here, from the database clock, and is what
// Deadlines resolves on.
//
// sent_at is also bounded against the incident's own timeline: a submission
// cannot predate the incident it reports, and cannot be in the future. Neither
// is a defence against a determined operator — the honest limit of this record
// is that AEGIS cannot witness a filing to a regulator, only that it was told
// about one — but both reject the mistakes and the crude forgeries, and the
// gap between claim and witness is now visible to anyone reading the report.
func (s *PGStore) RecordNotification(ctx context.Context, tenant, id string, n Notification) error {
	switch n.Kind {
	case KindEarlyWarning, KindNotification, KindFinalReport:
	default:
		return fmt.Errorf("%w: unknown notification kind %q", ErrInvalid, n.Kind)
	}

	return s.withTenantTx(ctx, tenant, func(tx *sql.Tx) error {
		var detectedAt, dbNow time.Time
		err := tx.QueryRowContext(ctx,
			`SELECT detected_at, NOW() FROM incidents WHERE tenant_id = $1 AND id = $2`,
			tenantOr(tenant), id).Scan(&detectedAt, &dbNow)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		if n.SentAt.IsZero() {
			n.SentAt = dbNow.UTC()
		}
		if n.SentAt.Before(detectedAt) {
			return fmt.Errorf("%w: sent_at %s precedes the incident's detection at %s",
				ErrInvalid, n.SentAt.UTC().Format(time.RFC3339), detectedAt.UTC().Format(time.RFC3339))
		}
		// A small allowance for clock skew between the operator's system and
		// the database; beyond that a future submission is not a filing that
		// happened, and accepting one would let a deadline be met in advance.
		if n.SentAt.After(dbNow.Add(clockSkewAllowance)) {
			return fmt.Errorf("%w: sent_at %s is in the future",
				ErrInvalid, n.SentAt.UTC().Format(time.RFC3339))
		}
		n.RecordedAt = dbNow.UTC()

		raw, err := json.Marshal([]Notification{n})
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
UPDATE incidents SET notifications = notifications || $3::jsonb
WHERE tenant_id = $1 AND id = $2`, tenantOr(tenant), id, string(raw))
		if err != nil {
			return err
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// clockSkewAllowance is how far ahead of the database clock a claimed
// submission time may sit before it is refused.
const clockSkewAllowance = 5 * time.Minute

// Stats summarises the incident record for the compliance report.
type Stats struct {
	Total int `json:"total"`
	Open  int `json:"open"`
	// Contained is counted separately from Open. Art. 17 is about a lifecycle,
	// and a report that folds "contained" into "open" describes a queue rather
	// than a process — which is the opposite of the thing being evidenced.
	Contained      int `json:"contained"`
	Closed         int `json:"closed"`
	Classified     int `json:"classified"`
	Notified       int `json:"notified"`
	Overdue        int `json:"overdue"`
	SeverityByHand int `json:"severity_confirmed"`
}

// Summarise counts what the compliance mapping needs to decide which articles
// are actually evidenced.
func Summarise(list []Incident, sched Schedule, now time.Time) Stats {
	var st Stats
	for i := range list {
		inc := &list[i]
		st.Total++
		switch inc.Status {
		case StatusClosed:
			st.Closed++
		case StatusContained:
			st.Contained++
		default:
			st.Open++
		}
		if inc.Classification.Complete() {
			st.Classified++
		}
		if len(inc.Notifications) > 0 {
			st.Notified++
		}
		if inc.Overdue(sched, now) {
			st.Overdue++
		}
		if inc.SeverityConfirmed {
			st.SeverityByHand++
		}
	}
	return st
}
