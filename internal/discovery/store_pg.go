package discovery

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/lib/pq" // PostgreSQL driver + array support
)

// catalogSchema creates the catalog tables and indices if they do not exist.
const catalogSchema = `
-- Tables carry a tenant_id (ADR-001) so one tenant's catalog is fully isolated
-- from another's. Fresh installs get the composite primary keys below; existing
-- single-tenant installs are migrated by the idempotent ALTER/INDEX statements
-- that follow, with their pre-existing rows backfilled to the 'default' tenant.
CREATE TABLE IF NOT EXISTS api_endpoints (
	tenant_id          TEXT NOT NULL DEFAULT 'default',
	id                 TEXT NOT NULL,
	method             TEXT NOT NULL,
	path_template      TEXT NOT NULL,
	first_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	request_count      BIGINT NOT NULL DEFAULT 0,
	error_count        BIGINT NOT NULL DEFAULT 0,
	auth_present_count BIGINT NOT NULL DEFAULT 0,
	anon_count         BIGINT NOT NULL DEFAULT 0,
	pii_count          BIGINT NOT NULL DEFAULT 0,
	pii_types          TEXT[] NOT NULL DEFAULT '{}',
	latency_ms_sum     BIGINT NOT NULL DEFAULT 0,
	latency_samples    BIGINT NOT NULL DEFAULT 0,
	posture            TEXT   NOT NULL DEFAULT 'unprotected',
	risk_score         INT    NOT NULL DEFAULT 0,
	route_path         TEXT   NOT NULL DEFAULT '',
	PRIMARY KEY (tenant_id, id)
);

-- Per-status counters live in their own table so concurrent increments sum
-- correctly (a jsonb "||" merge would overwrite keys instead of adding).
CREATE TABLE IF NOT EXISTS api_endpoint_status (
	tenant_id   TEXT NOT NULL DEFAULT 'default',
	endpoint_id TEXT NOT NULL,
	status      INT  NOT NULL,
	count       BIGINT NOT NULL DEFAULT 0,
	PRIMARY KEY (tenant_id, endpoint_id, status)
);

CREATE TABLE IF NOT EXISTS api_consumers (
	tenant_id     TEXT NOT NULL DEFAULT 'default',
	id            TEXT NOT NULL,
	kind          TEXT NOT NULL,
	label         TEXT NOT NULL,
	first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	request_count BIGINT NOT NULL DEFAULT 0,
	error_count   BIGINT NOT NULL DEFAULT 0,
	PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS api_endpoint_consumers (
	tenant_id     TEXT NOT NULL DEFAULT 'default',
	endpoint_id   TEXT NOT NULL,
	consumer_id   TEXT NOT NULL,
	request_count BIGINT NOT NULL DEFAULT 0,
	last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (tenant_id, endpoint_id, consumer_id)
);

-- Idempotent migration for installs created before multi-tenancy (the column
-- adds with a 'default' backfill; CREATE TABLE above is skipped when the table
-- already exists).
ALTER TABLE api_endpoints          ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE api_endpoints          ADD COLUMN IF NOT EXISTS pii_types TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE api_endpoint_status    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE api_consumers          ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE api_endpoint_consumers ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

-- Unique indexes matching the ON CONFLICT targets, so upserts work whether the
-- table was freshly created (composite PK) or migrated (legacy PK still on id).
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_endpoints_tid          ON api_endpoints (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_endpoint_status_tid    ON api_endpoint_status (tenant_id, endpoint_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_consumers_tid          ON api_consumers (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_endpoint_consumers_tid ON api_endpoint_consumers (tenant_id, endpoint_id, consumer_id);

-- Tenant-leading read indexes.
CREATE INDEX IF NOT EXISTS idx_api_endpoints_last_seen ON api_endpoints (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_risk      ON api_endpoints (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_api_consumers_last_seen ON api_consumers (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_epc_consumer            ON api_endpoint_consumers (tenant_id, consumer_id);

-- Row-Level Security (ADR-001, phase 2b). RLS is a fail-closed backstop on
-- top of the explicit "WHERE tenant_id" we already issue: a forgotten filter
-- or a SQL injection attempting to peek at another tenant returns zero rows
-- instead of leaking data. Reads/writes outside an explicit tenant scope
-- (when app.tenant_id is NULL) match nothing because NULL = anything is NULL.
--
-- The escape hatch is app.tenant_id = '*', used by maintenance code that must
-- legitimately span tenants (bootstrap, summary jobs). Code paths that talk
-- to the catalog go through pgStore.withTenantTx which always sets the GUC.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['api_endpoints','api_endpoint_status','api_consumers','api_endpoint_consumers'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    -- FORCE applies the policy even to the table owner, so a connection that
    -- forgets to SET LOCAL app.tenant_id sees no rows instead of all of them.
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = current_setting('app.tenant_id', true)
          OR current_setting('app.tenant_id', true) = '*')
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
          OR current_setting('app.tenant_id', true) = '*')$p$, t);
  END LOOP;
END $$;
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
	// RLS gotcha: PostgreSQL superusers and roles with BYPASSRLS automatically
	// skip every policy, defeating the fail-closed backstop installed above.
	// Warn loudly at startup so the operator can either ALTER ROLE
	// <user> NOSUPERUSER NOBYPASSRLS, or wire AEGIS to a dedicated app role.
	var rolsuper, rolbypass bool
	if err := db.QueryRowContext(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&rolsuper, &rolbypass); err == nil && (rolsuper || rolbypass) {
		log.Error("RLS DEGRADED: AEGIS database role bypasses Row-Level Security; "+
			"run `ALTER ROLE <user> NOSUPERUSER NOBYPASSRLS;` or use a non-privileged "+
			"app role in production",
			map[string]any{"superuser": rolsuper, "bypassrls": rolbypass})
	}
	return &pgStore{db: db, log: log}, nil
}

func (s *pgStore) Close() error { return s.db.Close() }

// withTenantTx opens a transaction, pins app.tenant_id for its lifetime, and
// runs fn against it. The GUC enforces Row-Level Security on every statement
// inside fn: if fn forgets to write `WHERE tenant_id = ...`, RLS turns the
// query into a no-op for any tenant other than `tenantID`. Pass "*" to span
// every tenant (maintenance/bootstrap only).
//
// set_config(..., is_local=true) is the SQL equivalent of SET LOCAL with a
// parameter placeholder, since the bare SET LOCAL syntax does not accept $1.
func (s *pgStore) withTenantTx(ctx context.Context, tenantID string, fn func(*sql.Tx) error) error {
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

// upsertEndpoint merges an aggregated delta for one endpoint into the table,
// then increments its per-status counters.
func (s *pgStore) upsertEndpoint(ctx context.Context, a *epAgg) error {
	const q = `
INSERT INTO api_endpoints
	(tenant_id, id, method, path_template, first_seen, last_seen, request_count, error_count,
	 auth_present_count, anon_count, pii_count, latency_ms_sum, latency_samples,
	 posture, risk_score, route_path, pii_types)
VALUES ($1,$2,$3,$4,NOW(),NOW(),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (tenant_id, id) DO UPDATE SET
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
	route_path         = EXCLUDED.route_path,
	-- union the observed data-class sets so the column accumulates every type
	-- ever seen on this endpoint, deduplicated.
	pii_types          = ARRAY(SELECT DISTINCT unnest(api_endpoints.pii_types || EXCLUDED.pii_types))`
	return s.withTenantTx(ctx, a.tenant, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, q,
			tenantOr(a.tenant), a.id, a.method, a.pathTemplate, a.requestCount, a.errorCount,
			a.authPresent, a.anonCount, a.piiCount, a.latencyMsSum, a.latencySamples,
			a.posture, a.riskScore, a.routePath, pq.Array(piiTypeSlice(a.piiTypes))); err != nil {
			return err
		}
		const sq = `
INSERT INTO api_endpoint_status (tenant_id, endpoint_id, status, count)
VALUES ($1,$2,$3,$4)
ON CONFLICT (tenant_id, endpoint_id, status) DO UPDATE SET
	count = api_endpoint_status.count + EXCLUDED.count`
		for status, count := range a.statusDist {
			if _, err := tx.ExecContext(ctx, sq, tenantOr(a.tenant), a.id, status, count); err != nil {
				return err
			}
		}
		return nil
	})
}

// tenantOr defaults an empty tenant to the default tenant, so a path that did
// not resolve a tenant still writes to a valid scope rather than an empty one.
func tenantOr(t string) string {
	if t == "" {
		return "default"
	}
	return t
}

func (s *pgStore) upsertConsumer(ctx context.Context, c *consumerAgg) error {
	const q = `
INSERT INTO api_consumers (tenant_id, id, kind, label, first_seen, last_seen, request_count, error_count)
VALUES ($1,$2,$3,$4,NOW(),NOW(),$5,$6)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	last_seen     = NOW(),
	request_count = api_consumers.request_count + EXCLUDED.request_count,
	error_count   = api_consumers.error_count + EXCLUDED.error_count`
	return s.withTenantTx(ctx, c.tenant, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, q, tenantOr(c.tenant), c.id, c.kind, c.label, c.requestCount, c.errorCount)
		return err
	})
}

func (s *pgStore) upsertEndpointConsumer(ctx context.Context, tenantID, endpointID, consumerID string, count int64) error {
	const q = `
INSERT INTO api_endpoint_consumers (tenant_id, endpoint_id, consumer_id, request_count, last_seen)
VALUES ($1,$2,$3,$4,NOW())
ON CONFLICT (tenant_id, endpoint_id, consumer_id) DO UPDATE SET
	request_count = api_endpoint_consumers.request_count + EXCLUDED.request_count,
	last_seen     = NOW()`
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, q, tenantOr(tenantID), endpointID, consumerID, count)
		return err
	})
}

// ── Queries (used by the admin API) ─────────────────────────────────────────

func (s *pgStore) listEndpoints(ctx context.Context, tenantID string, f EndpointFilter) ([]Endpoint, error) {
	q := `SELECT id, method, path_template, first_seen, last_seen, request_count,
		error_count, auth_present_count, anon_count, pii_count, latency_ms_sum,
		latency_samples, posture, risk_score, route_path, pii_types
		FROM api_endpoints WHERE tenant_id = $1`
	args := []any{tenantOr(tenantID)}
	n := 2
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

	var out []Endpoint
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		out = []Endpoint{}
		for rows.Next() {
			e, err := scanEndpoint(rows)
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgStore) getEndpoint(ctx context.Context, tenantID, id string) (*Endpoint, []EndpointConsumer, error) {
	tid := tenantOr(tenantID)
	var (
		e         Endpoint
		consumers []EndpointConsumer
		found     bool
	)
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT id, method, path_template, first_seen,
			last_seen, request_count, error_count, auth_present_count, anon_count,
			pii_count, latency_ms_sum, latency_samples, posture,
			risk_score, route_path, pii_types FROM api_endpoints WHERE tenant_id = $1 AND id = $2`, tid, id)
		scanned, err := scanEndpoint(row)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		e = scanned
		found = true

		e.StatusDist = map[string]int64{}
		if srows, serr := tx.QueryContext(ctx,
			`SELECT status, count FROM api_endpoint_status WHERE tenant_id = $1 AND endpoint_id = $2`, tid, id); serr == nil {
			for srows.Next() {
				var st int
				var cnt int64
				if srows.Scan(&st, &cnt) == nil {
					e.StatusDist[fmt.Sprintf("%d", st)] = cnt
				}
			}
			_ = srows.Close()
		}

		rows, err := tx.QueryContext(ctx, `SELECT c.id, c.kind, c.label,
			ec.request_count, ec.last_seen
			FROM api_endpoint_consumers ec JOIN api_consumers c
			  ON c.id = ec.consumer_id AND c.tenant_id = ec.tenant_id
			WHERE ec.tenant_id = $1 AND ec.endpoint_id = $2 ORDER BY ec.request_count DESC LIMIT 200`, tid, id)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		consumers = []EndpointConsumer{}
		for rows.Next() {
			var ec EndpointConsumer
			if err := rows.Scan(&ec.ID, &ec.Kind, &ec.Label, &ec.RequestCount, &ec.LastSeen); err != nil {
				return err
			}
			consumers = append(consumers, ec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, nil
	}
	return &e, consumers, nil
}

func (s *pgStore) listConsumers(ctx context.Context, tenantID string, limit int) ([]Consumer, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var out []Consumer
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT c.id, c.kind, c.label,
			c.first_seen, c.last_seen, c.request_count, c.error_count,
			(SELECT COUNT(*) FROM api_endpoint_consumers ec
			 WHERE ec.tenant_id = c.tenant_id AND ec.consumer_id = c.id)
			FROM api_consumers c WHERE c.tenant_id = $1
			ORDER BY c.request_count DESC LIMIT $2`, tenantOr(tenantID), limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		out = []Consumer{}
		for rows.Next() {
			var c Consumer
			if err := rows.Scan(&c.ID, &c.Kind, &c.Label, &c.FirstSeen, &c.LastSeen,
				&c.RequestCount, &c.ErrorCount, &c.EndpointsTouched); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgStore) postureSummary(ctx context.Context, tenantID string) (PostureSummary, error) {
	var sum PostureSummary
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT posture, COUNT(*) FROM api_endpoints WHERE tenant_id = $1 GROUP BY posture`, tenantOr(tenantID))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var p string
			var n int
			if err := rows.Scan(&p, &n); err != nil {
				return err
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
		return rows.Err()
	})
	if err != nil {
		return sum, err
	}
	if sum.Total > 0 {
		sum.CoveragePct = int(float64(sum.Protected) / float64(sum.Total) * 100)
	}
	// TopRisky runs in its own transaction — listEndpoints already wraps itself.
	top, err := s.listEndpoints(ctx, tenantID, EndpointFilter{MinRisk: 1, Limit: 10})
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
		&e.RiskScore, &e.RoutePath, pq.Array(&e.PIITypes)); err != nil {
		return e, err
	}
	if e.latencySamples > 0 {
		e.AvgLatencyMs = e.latencyMsSum / e.latencySamples
	}
	return e, nil
}

// piiTypeSlice converts the aggregator's data-type set into a sorted slice for
// stable storage (and so tests/diffs are deterministic).
func piiTypeSlice(set map[string]bool) []string {
	if len(set) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
