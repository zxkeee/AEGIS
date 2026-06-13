package discovery

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// catalogSchema creates the catalog tables and indices if they do not exist.
const catalogSchema = `
CREATE TABLE IF NOT EXISTS api_endpoints (
	id                 TEXT PRIMARY KEY,
	method             TEXT NOT NULL,
	path_template      TEXT NOT NULL,
	first_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	request_count      BIGINT NOT NULL DEFAULT 0,
	error_count        BIGINT NOT NULL DEFAULT 0,
	auth_present_count BIGINT NOT NULL DEFAULT 0,
	anon_count         BIGINT NOT NULL DEFAULT 0,
	pii_count          BIGINT NOT NULL DEFAULT 0,
	latency_ms_sum     BIGINT NOT NULL DEFAULT 0,
	latency_samples    BIGINT NOT NULL DEFAULT 0,
	posture            TEXT   NOT NULL DEFAULT 'unprotected',
	risk_score         INT    NOT NULL DEFAULT 0,
	route_path         TEXT   NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_last_seen ON api_endpoints (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_risk ON api_endpoints (risk_score DESC);

-- Per-status counters live in their own table so concurrent increments sum
-- correctly (a jsonb "||" merge would overwrite keys instead of adding).
CREATE TABLE IF NOT EXISTS api_endpoint_status (
	endpoint_id TEXT NOT NULL,
	status      INT  NOT NULL,
	count       BIGINT NOT NULL DEFAULT 0,
	PRIMARY KEY (endpoint_id, status)
);

CREATE TABLE IF NOT EXISTS api_consumers (
	id            TEXT PRIMARY KEY,
	kind          TEXT NOT NULL,
	label         TEXT NOT NULL,
	first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	request_count BIGINT NOT NULL DEFAULT 0,
	error_count   BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_consumers_last_seen ON api_consumers (last_seen DESC);

CREATE TABLE IF NOT EXISTS api_endpoint_consumers (
	endpoint_id   TEXT NOT NULL,
	consumer_id   TEXT NOT NULL,
	request_count BIGINT NOT NULL DEFAULT 0,
	last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (endpoint_id, consumer_id)
);
CREATE INDEX IF NOT EXISTS idx_epc_consumer ON api_endpoint_consumers (consumer_id);
`

// pgStore is the PostgreSQL persistence layer for the catalog.
type pgStore struct {
	db  *sql.DB
	log Logger
}

func newPGStore(dsn string, log Logger) (*pgStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("discovery: pg connect: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("discovery: pg ping: %w", err)
	}
	if _, err := db.ExecContext(ctx, catalogSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("discovery: pg migrate: %w", err)
	}
	return &pgStore{db: db, log: log}, nil
}

func (s *pgStore) Close() error { return s.db.Close() }

// upsertEndpoint merges an aggregated delta for one endpoint into the table,
// then increments its per-status counters.
func (s *pgStore) upsertEndpoint(ctx context.Context, a *epAgg) error {
	const q = `
INSERT INTO api_endpoints
	(id, method, path_template, first_seen, last_seen, request_count, error_count,
	 auth_present_count, anon_count, pii_count, latency_ms_sum, latency_samples,
	 posture, risk_score, route_path)
VALUES ($1,$2,$3,NOW(),NOW(),$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (id) DO UPDATE SET
	last_seen          = NOW(),
	request_count      = api_endpoints.request_count + EXCLUDED.request_count,
	error_count        = api_endpoints.error_count + EXCLUDED.error_count,
	auth_present_count = api_endpoints.auth_present_count + EXCLUDED.auth_present_count,
	anon_count         = api_endpoints.anon_count + EXCLUDED.anon_count,
	pii_count          = api_endpoints.pii_count + EXCLUDED.pii_count,
	latency_ms_sum     = api_endpoints.latency_ms_sum + EXCLUDED.latency_ms_sum,
	latency_samples    = api_endpoints.latency_samples + EXCLUDED.latency_samples,
	posture            = EXCLUDED.posture,
	risk_score         = EXCLUDED.risk_score,
	route_path         = EXCLUDED.route_path`
	if _, err := s.db.ExecContext(ctx, q,
		a.id, a.method, a.pathTemplate, a.requestCount, a.errorCount,
		a.authPresent, a.anonCount, a.piiCount, a.latencyMsSum, a.latencySamples,
		a.posture, a.riskScore, a.routePath); err != nil {
		return err
	}

	const sq = `
INSERT INTO api_endpoint_status (endpoint_id, status, count)
VALUES ($1,$2,$3)
ON CONFLICT (endpoint_id, status) DO UPDATE SET
	count = api_endpoint_status.count + EXCLUDED.count`
	for status, count := range a.statusDist {
		if _, err := s.db.ExecContext(ctx, sq, a.id, status, count); err != nil {
			return err
		}
	}
	return nil
}

func (s *pgStore) upsertConsumer(ctx context.Context, c *consumerAgg) error {
	const q = `
INSERT INTO api_consumers (id, kind, label, first_seen, last_seen, request_count, error_count)
VALUES ($1,$2,$3,NOW(),NOW(),$4,$5)
ON CONFLICT (id) DO UPDATE SET
	last_seen     = NOW(),
	request_count = api_consumers.request_count + EXCLUDED.request_count,
	error_count   = api_consumers.error_count + EXCLUDED.error_count`
	_, err := s.db.ExecContext(ctx, q, c.id, c.kind, c.label, c.requestCount, c.errorCount)
	return err
}

func (s *pgStore) upsertEndpointConsumer(ctx context.Context, endpointID, consumerID string, count int64) error {
	const q = `
INSERT INTO api_endpoint_consumers (endpoint_id, consumer_id, request_count, last_seen)
VALUES ($1,$2,$3,NOW())
ON CONFLICT (endpoint_id, consumer_id) DO UPDATE SET
	request_count = api_endpoint_consumers.request_count + EXCLUDED.request_count,
	last_seen     = NOW()`
	_, err := s.db.ExecContext(ctx, q, endpointID, consumerID, count)
	return err
}

// ── Queries (used by the admin API) ─────────────────────────────────────────

func (s *pgStore) listEndpoints(ctx context.Context, f EndpointFilter) ([]Endpoint, error) {
	q := `SELECT id, method, path_template, first_seen, last_seen, request_count,
		error_count, auth_present_count, anon_count, pii_count, latency_ms_sum,
		latency_samples, posture, risk_score, route_path
		FROM api_endpoints WHERE 1=1`
	args := []any{}
	n := 1
	if f.Posture != "" {
		q += fmt.Sprintf(" AND posture = $%d", n)
		args = append(args, f.Posture)
		n++
	}
	if f.Search != "" {
		q += fmt.Sprintf(" AND path_template ILIKE $%d", n)
		args = append(args, "%"+f.Search+"%")
		n++
	}
	if f.MinRisk > 0 {
		q += fmt.Sprintf(" AND risk_score >= $%d", n)
		args = append(args, f.MinRisk)
		n++
	}
	q += " ORDER BY risk_score DESC, request_count DESC"
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	// Only constant fragments and $N placeholders are concatenated; every
	// user-supplied value is passed via args and parameterized by the driver.
	q += fmt.Sprintf(" LIMIT $%d", n) // #nosec G202 -- parameterized query, no value concatenation
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []Endpoint{}
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *pgStore) getEndpoint(ctx context.Context, id string) (*Endpoint, []EndpointConsumer, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, method, path_template, first_seen,
		last_seen, request_count, error_count, auth_present_count, anon_count,
		pii_count, latency_ms_sum, latency_samples, posture,
		risk_score, route_path FROM api_endpoints WHERE id = $1`, id)
	e, err := scanEndpoint(row)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	// Load per-status distribution from its dedicated table.
	e.StatusDist = map[string]int64{}
	if srows, serr := s.db.QueryContext(ctx,
		`SELECT status, count FROM api_endpoint_status WHERE endpoint_id = $1`, id); serr == nil {
		for srows.Next() {
			var st int
			var cnt int64
			if srows.Scan(&st, &cnt) == nil {
				e.StatusDist[fmt.Sprintf("%d", st)] = cnt
			}
		}
		_ = srows.Close()
	}

	rows, err := s.db.QueryContext(ctx, `SELECT c.id, c.kind, c.label,
		ec.request_count, ec.last_seen
		FROM api_endpoint_consumers ec JOIN api_consumers c ON c.id = ec.consumer_id
		WHERE ec.endpoint_id = $1 ORDER BY ec.request_count DESC LIMIT 200`, id)
	if err != nil {
		return &e, nil, err
	}
	defer func() { _ = rows.Close() }()
	consumers := []EndpointConsumer{}
	for rows.Next() {
		var ec EndpointConsumer
		if err := rows.Scan(&ec.ID, &ec.Kind, &ec.Label, &ec.RequestCount, &ec.LastSeen); err != nil {
			return &e, nil, err
		}
		consumers = append(consumers, ec)
	}
	return &e, consumers, rows.Err()
}

func (s *pgStore) listConsumers(ctx context.Context, limit int) ([]Consumer, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.id, c.kind, c.label,
		c.first_seen, c.last_seen, c.request_count, c.error_count,
		(SELECT COUNT(*) FROM api_endpoint_consumers ec WHERE ec.consumer_id = c.id)
		FROM api_consumers c ORDER BY c.request_count DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Consumer{}
	for rows.Next() {
		var c Consumer
		if err := rows.Scan(&c.ID, &c.Kind, &c.Label, &c.FirstSeen, &c.LastSeen,
			&c.RequestCount, &c.ErrorCount, &c.EndpointsTouched); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *pgStore) postureSummary(ctx context.Context) (PostureSummary, error) {
	var sum PostureSummary
	rows, err := s.db.QueryContext(ctx,
		`SELECT posture, COUNT(*) FROM api_endpoints GROUP BY posture`)
	if err != nil {
		return sum, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			return sum, err
		}
		switch p {
		case PostureProtected:
			sum.Protected = n
		case PosturePartial:
			sum.Partial = n
		case PostureUnprotected:
			sum.Unprotected = n
		case PostureShadow:
			sum.Shadow = n
		}
		sum.Total += n
	}
	if err := rows.Err(); err != nil {
		return sum, err
	}
	if sum.Total > 0 {
		sum.CoveragePct = int(float64(sum.Protected) / float64(sum.Total) * 100)
	}

	top, err := s.listEndpoints(ctx, EndpointFilter{MinRisk: 1, Limit: 10})
	if err == nil {
		sum.TopRisky = top
	}
	return sum, nil
}

// rowScanner abstracts *sql.Row and *sql.Rows for shared scanning.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanEndpoint(r rowScanner) (Endpoint, error) {
	var e Endpoint
	if err := r.Scan(&e.ID, &e.Method, &e.PathTemplate, &e.FirstSeen, &e.LastSeen,
		&e.RequestCount, &e.ErrorCount, &e.AuthPresentCount, &e.AnonCount,
		&e.PIICount, &e.latencyMsSum, &e.latencySamples, &e.Posture,
		&e.RiskScore, &e.RoutePath); err != nil {
		return e, err
	}
	if e.latencySamples > 0 {
		e.AvgLatencyMs = e.latencyMsSum / e.latencySamples
	}
	return e, nil
}
