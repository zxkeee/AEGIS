package discovery

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/pgtest"
)

// pgDSN returns the test PostgreSQL DSN or skips when unset (local runs without
// a database). CI provides POSTGRES_DSN via the postgres service.
func pgDSN(t *testing.T) string {
	t.Helper()
	return pgtest.DSN(t, "test_discovery")
}

type nopLogger struct{}

func (nopLogger) Info(string, ...map[string]any)  {}
func (nopLogger) Error(string, ...map[string]any) {}

func freshStore(t *testing.T) *pgStore {
	t.Helper()
	s, err := newPGStore(pgDSN(t), nopLogger{})
	if err != nil {
		t.Fatalf("newPGStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	// Deterministic state for each test.
	_, _ = s.db.Exec(`TRUNCATE api_endpoints, api_endpoint_status, api_consumers, api_endpoint_consumers, api_specs`)
	return s
}

func TestPG_UpsertAndQueryEndpoint(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	a := &epAgg{
		tenant: "acme", id: "GET:/users/{id}", method: "GET", pathTemplate: "/users/{id}",
		requestCount: 3, errorCount: 1, authPresent: 2, anonCount: 1, piiCount: 1,
		latencyMsSum: 60, latencySamples: 3, posture: "partial", riskScore: 55,
		routePath: "/users", statusDist: map[int]int64{200: 2, 500: 1},
	}
	if err := s.upsertEndpoint(ctx, a); err != nil {
		t.Fatalf("upsertEndpoint: %v", err)
	}
	// Upsert again: counters must accumulate, not overwrite.
	if err := s.upsertEndpoint(ctx, a); err != nil {
		t.Fatalf("upsertEndpoint 2: %v", err)
	}

	eps, err := s.listEndpoints(ctx, "acme", EndpointFilter{Limit: 10})
	if err != nil {
		t.Fatalf("listEndpoints: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].RequestCount != 6 || eps[0].ErrorCount != 2 {
		t.Fatalf("counters did not accumulate: %+v", eps[0])
	}
	if eps[0].AvgLatencyMs != 20 { // 120 / 6
		t.Fatalf("avg latency = %d, want 20", eps[0].AvgLatencyMs)
	}

	// getEndpoint returns the row and its status distribution.
	e, _, err := s.getEndpoint(ctx, "acme", "GET:/users/{id}")
	if err != nil || e == nil {
		t.Fatalf("getEndpoint: %v (e=%v)", err, e)
	}
	if e.StatusDist["200"] != 4 || e.StatusDist["500"] != 2 {
		t.Fatalf("status dist wrong: %+v", e.StatusDist)
	}

	// Unknown id → nil, no error.
	missing, _, err := s.getEndpoint(ctx, "acme", "GET:/nope")
	if err != nil || missing != nil {
		t.Fatalf("missing endpoint: e=%v err=%v", missing, err)
	}
}

// TestPG_CrossTenantIsolation is the core acceptance test: tenant A must never
// see tenant B's endpoints, consumers or posture (ADR-001 release gate).
func TestPG_CrossTenantIsolation(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	// Same endpoint id and consumer id under two different tenants.
	_ = s.upsertEndpoint(ctx, &epAgg{tenant: "acme", id: "GET:/x", method: "GET", pathTemplate: "/x", requestCount: 1, posture: "protected", statusDist: map[int]int64{200: 1}})
	_ = s.upsertEndpoint(ctx, &epAgg{tenant: "globex", id: "GET:/x", method: "GET", pathTemplate: "/x", requestCount: 9, posture: "unprotected", statusDist: map[int]int64{500: 9}})
	_ = s.upsertConsumer(ctx, &consumerAgg{tenant: "acme", id: "jwt:u", kind: "jwt", label: "u", requestCount: 1})
	_ = s.upsertConsumer(ctx, &consumerAgg{tenant: "globex", id: "jwt:u", kind: "jwt", label: "u", requestCount: 9})

	// listEndpoints is scoped.
	acme, _ := s.listEndpoints(ctx, "acme", EndpointFilter{Limit: 10})
	if len(acme) != 1 || acme[0].RequestCount != 1 || acme[0].Posture != "protected" {
		t.Fatalf("acme leaked globex data: %+v", acme)
	}
	globex, _ := s.listEndpoints(ctx, "globex", EndpointFilter{Limit: 10})
	if len(globex) != 1 || globex[0].RequestCount != 9 {
		t.Fatalf("globex view wrong: %+v", globex)
	}

	// getEndpoint is scoped: acme's id must not return globex's row.
	e, _, _ := s.getEndpoint(ctx, "acme", "GET:/x")
	if e == nil || e.Posture != "protected" {
		t.Fatalf("getEndpoint cross-tenant leak: %+v", e)
	}

	// A tenant with no data sees nothing.
	none, _ := s.listEndpoints(ctx, "ghost", EndpointFilter{Limit: 10})
	if len(none) != 0 {
		t.Fatalf("unknown tenant saw %d endpoints", len(none))
	}

	// Consumers and posture summary are scoped too.
	if cons, _ := s.listConsumers(ctx, "acme", 10); len(cons) != 1 || cons[0].RequestCount != 1 {
		t.Fatalf("consumer isolation failed: %+v", cons)
	}
	sumA, _ := s.postureSummary(ctx, "acme")
	if sumA.Total != 1 || sumA.Protected != 1 || sumA.Unprotected != 0 {
		t.Fatalf("acme posture leaked globex: %+v", sumA)
	}
}

func TestPG_FilterByPostureAndRisk(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	_ = s.upsertEndpoint(ctx, &epAgg{tenant: "default", id: "a", method: "GET", pathTemplate: "/a", requestCount: 1, posture: "protected", riskScore: 10, statusDist: map[int]int64{}})
	_ = s.upsertEndpoint(ctx, &epAgg{tenant: "default", id: "b", method: "GET", pathTemplate: "/b", requestCount: 1, posture: "unprotected", riskScore: 90, statusDist: map[int]int64{}})

	hi, err := s.listEndpoints(ctx, "default", EndpointFilter{MinRisk: 50, Limit: 10})
	if err != nil {
		t.Fatalf("listEndpoints: %v", err)
	}
	if len(hi) != 1 || hi[0].ID != "b" {
		t.Fatalf("MinRisk filter wrong: %+v", hi)
	}

	prot, _ := s.listEndpoints(ctx, "default", EndpointFilter{Posture: "protected", Limit: 10})
	if len(prot) != 1 || prot[0].ID != "a" {
		t.Fatalf("posture filter wrong: %+v", prot)
	}
}

func TestPG_ConsumersAndPostureSummary(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()
	_ = s.upsertEndpoint(ctx, &epAgg{tenant: "default", id: "ep1", method: "GET", pathTemplate: "/ep1", requestCount: 1, posture: "protected", statusDist: map[int]int64{}})
	_ = s.upsertEndpoint(ctx, &epAgg{tenant: "default", id: "ep2", method: "GET", pathTemplate: "/ep2", requestCount: 1, posture: "shadow", statusDist: map[int]int64{}})
	if err := s.upsertConsumer(ctx, &consumerAgg{tenant: "default", id: "jwt:u", kind: "jwt", label: "u", requestCount: 5, errorCount: 1}); err != nil {
		t.Fatalf("upsertConsumer: %v", err)
	}
	if err := s.upsertEndpointConsumer(ctx, "default", "ep1", "jwt:u", 5); err != nil {
		t.Fatalf("upsertEndpointConsumer: %v", err)
	}

	cons, err := s.listConsumers(ctx, "default", 10)
	if err != nil {
		t.Fatalf("listConsumers: %v", err)
	}
	if len(cons) != 1 || cons[0].RequestCount != 5 || cons[0].EndpointsTouched != 1 {
		t.Fatalf("consumer query wrong: %+v", cons)
	}

	sum, err := s.postureSummary(ctx, "default")
	if err != nil {
		t.Fatalf("postureSummary: %v", err)
	}
	if sum.Total != 2 || sum.Protected != 1 || sum.Shadow != 1 {
		t.Fatalf("posture summary wrong: %+v", sum)
	}
}

// TestPG_CatalogEndToEnd exercises the full NewCatalog → Record → flush → read
// path through the background worker.
func TestPG_CatalogEndToEnd(t *testing.T) {
	dsn := pgDSN(t)
	// Clean slate.
	s, err := newPGStore(dsn, nopLogger{})
	if err != nil {
		t.Fatalf("newPGStore: %v", err)
	}
	_, _ = s.db.Exec(`TRUNCATE api_endpoints, api_endpoint_status, api_consumers, api_endpoint_consumers, api_specs`)
	_ = s.Close()

	cat, err := NewCatalog(dsn, NewPostureEngine(config.GatewayConfig{}), nopLogger{})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}

	cat.Record(Observation{Method: "GET", Path: "/orders/1", Status: 200, AuthPresent: true, ConsumerSubject: "u", LatencyMs: 5})
	cat.Record(Observation{Method: "GET", Path: "/orders/2", Status: 200, AuthPresent: true, ConsumerSubject: "u", LatencyMs: 5})

	// Close drains the buffer and flushes synchronously.
	if err := cat.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open to read what the worker persisted.
	cat2, err := NewCatalog(dsn, NewPostureEngine(config.GatewayConfig{}), nopLogger{})
	if err != nil {
		t.Fatalf("NewCatalog 2: %v", err)
	}
	defer func() { _ = cat2.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	eps, err := cat2.ListEndpoints(ctx, EndpointFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	if len(eps) != 1 || eps[0].RequestCount != 2 {
		t.Fatalf("end-to-end catalog wrong: %+v", eps)
	}
	if eps[0].Controls == nil {
		t.Fatal("ListEndpoints should enrich with live controls")
	}
}

func TestPG_GraphData(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	// Two endpoints (one PII/unprotected), two consumers, three edges.
	if err := s.upsertEndpoint(ctx, &epAgg{tenant: "default", id: "ep_orders", method: "GET", pathTemplate: "/orders/{id}", requestCount: 10, posture: "unprotected", riskScore: 80, piiCount: 3, statusDist: map[int]int64{}}); err != nil {
		t.Fatalf("upsertEndpoint orders: %v", err)
	}
	_ = s.upsertEndpoint(ctx, &epAgg{tenant: "default", id: "ep_health", method: "GET", pathTemplate: "/health", requestCount: 2, posture: "protected", statusDist: map[int]int64{}})
	_ = s.upsertConsumer(ctx, &consumerAgg{tenant: "default", id: "jwt:alice", kind: "jwt", label: "alice", requestCount: 8})
	_ = s.upsertConsumer(ctx, &consumerAgg{tenant: "default", id: "ip:1.2.3.4", kind: "ip", label: "ip:1.2.3.4", requestCount: 4})
	_ = s.upsertEndpointConsumer(ctx, "default", "ep_orders", "jwt:alice", 8)
	_ = s.upsertEndpointConsumer(ctx, "default", "ep_orders", "ip:1.2.3.4", 2)
	_ = s.upsertEndpointConsumer(ctx, "default", "ep_health", "ip:1.2.3.4", 2)

	g, err := s.graphData(ctx, "default", 100)
	if err != nil {
		t.Fatalf("graphData: %v", err)
	}
	if len(g.Edges) != 3 {
		t.Fatalf("edges = %d, want 3", len(g.Edges))
	}
	if len(g.Nodes) != 4 { // 2 endpoints + 2 consumers
		t.Fatalf("nodes = %d, want 4", len(g.Nodes))
	}

	var orders *GraphNode
	for i := range g.Nodes {
		if g.Nodes[i].ID == "endpoint:ep_orders" {
			orders = &g.Nodes[i]
		}
	}
	if orders == nil {
		t.Fatal("orders endpoint node missing")
	}
	if orders.Type != "endpoint" || !orders.PII || orders.Posture != "unprotected" || orders.Method != "GET" {
		t.Fatalf("orders node = %+v", *orders)
	}
	// Edge endpoints are type-prefixed so they resolve to nodes.
	for _, e := range g.Edges {
		if len(e.Source) < 9 || e.Source[:9] != "consumer:" || len(e.Target) < 9 || e.Target[:9] != "endpoint:" {
			t.Fatalf("edge not type-prefixed: %+v", e)
		}
	}

	// Cross-tenant isolation: another tenant sees an empty graph.
	g2, err := s.graphData(ctx, "globex", 100)
	if err != nil {
		t.Fatalf("graphData globex: %v", err)
	}
	if len(g2.Nodes) != 0 || len(g2.Edges) != 0 {
		t.Fatalf("cross-tenant leak: %d nodes, %d edges", len(g2.Nodes), len(g2.Edges))
	}
}

// ── Retemplating after the learner rules on a position ───────────────────────

// The learner needs traffic before it can judge a position, so by the time it
// rules, the catalog already holds rows written under concrete paths. This is
// what turns those rows into the endpoint they were always part of — without
// it, the console keeps showing one row per object forever and the fix only
// applies to future requests.
func TestPG_RetemplateMergesRowsWrittenBeforeLearning(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	// Three repositories browsed before /api/v1/repos was known to hold owner
	// names, plus one row already carrying the template (traffic that arrived
	// after the rule was learned).
	rows := []struct {
		tmpl            string
		reqs, anon, pii int64
		status          map[int]int64
		posture         string
		risk            int
	}{
		{"/api/v1/repos/alice/x", 5, 5, 2, map[int]int64{200: 5}, "unprotected", 75},
		{"/api/v1/repos/bob/x", 3, 0, 1, map[int]int64{200: 2, 404: 1}, "partial", 40},
		{"/api/v1/repos/carol/x", 2, 2, 0, map[int]int64{200: 2}, "partial", 30},
		{"/api/v1/repos/{id}/x", 7, 1, 3, map[int]int64{200: 7}, "partial", 50},
	}
	for _, r := range rows {
		a := &epAgg{
			tenant: "acme", id: "GET " + r.tmpl, method: "GET", pathTemplate: r.tmpl,
			requestCount: r.reqs, anonCount: r.anon, piiCount: r.pii,
			posture: r.posture, riskScore: r.risk, statusDist: r.status,
			piiTypes: map[string]bool{"email": true},
		}
		if err := s.upsertEndpoint(ctx, a); err != nil {
			t.Fatalf("upsertEndpoint %s: %v", r.tmpl, err)
		}
	}

	// A different prefix must be left completely alone.
	untouched := &epAgg{
		tenant: "acme", id: "GET /api/v1/version", method: "GET",
		pathTemplate: "/api/v1/version", requestCount: 9, statusDist: map[int]int64{200: 9},
	}
	if err := s.upsertEndpoint(ctx, untouched); err != nil {
		t.Fatalf("upsertEndpoint version: %v", err)
	}

	if err := s.retemplateEndpoints(ctx, "acme", "/api/v1/repos"); err != nil {
		t.Fatalf("retemplateEndpoints: %v", err)
	}

	eps, err := s.listEndpoints(ctx, "acme", EndpointFilter{Limit: 50})
	if err != nil {
		t.Fatalf("listEndpoints: %v", err)
	}
	byTemplate := map[string]Endpoint{}
	for _, e := range eps {
		byTemplate[e.PathTemplate] = e
	}
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints after merge, got %d: %v", len(eps), byTemplate)
	}

	merged, ok := byTemplate["/api/v1/repos/{id}/x"]
	if !ok {
		t.Fatalf("merged template missing, got %v", byTemplate)
	}
	// Counters must be summed, not replaced: those requests really happened, and
	// posture and the findings' "N requests arrived without authentication" are
	// computed from them.
	if merged.RequestCount != 17 {
		t.Errorf("request_count = %d, want 17 (5+3+2+7)", merged.RequestCount)
	}
	if merged.AnonCount != 8 {
		t.Errorf("anon_count = %d, want 8 (5+0+2+1)", merged.AnonCount)
	}
	if merged.PIICount != 6 {
		t.Errorf("pii_count = %d, want 6 (2+1+0+3)", merged.PIICount)
	}
	// Worst posture and highest risk win — an endpoint unprotected for some of
	// its objects is unprotected.
	if merged.Posture != "unprotected" {
		t.Errorf("posture = %q, want unprotected", merged.Posture)
	}
	if merged.RiskScore != 75 {
		t.Errorf("risk_score = %d, want 75", merged.RiskScore)
	}

	if v := byTemplate["/api/v1/version"]; v.RequestCount != 9 {
		t.Errorf("unrelated endpoint changed: %+v", v)
	}

	// Status counters follow the merge, and the old rows are gone.
	// Read through withTenantTx: RLS is FORCEd on these tables, so a direct
	// query without the app.tenant_id GUC fails closed and returns nothing.
	statuses := map[int]int64{}
	if err := s.withTenantTx(ctx, "acme", func(tx *sql.Tx) error {
		srs, err := tx.QueryContext(ctx, `SELECT status, count FROM api_endpoint_status`)
		if err != nil {
			return err
		}
		defer func() { _ = srs.Close() }()
		for srs.Next() {
			var st int
			var n int64
			if err := srs.Scan(&st, &n); err != nil {
				return err
			}
			statuses[st] += n
		}
		return srs.Err()
	}); err != nil {
		t.Fatalf("query statuses: %v", err)
	}
	if statuses[200] != 25 || statuses[404] != 1 {
		t.Errorf("status distribution = %v, want 200:25 (16 merged + 9 version) and 404:1", statuses)
	}
}

// Retemplating must be safe to run again — the catalog calls it once per flush
// after a position collapses, and a retry after a partial failure must not
// double-count.
func TestPG_RetemplateIsIdempotent(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	a := &epAgg{
		tenant: "acme", id: "GET /api/v1/repos/alice/x", method: "GET",
		pathTemplate: "/api/v1/repos/alice/x", requestCount: 4,
		statusDist: map[int]int64{200: 4},
	}
	if err := s.upsertEndpoint(ctx, a); err != nil {
		t.Fatalf("upsertEndpoint: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.retemplateEndpoints(ctx, "acme", "/api/v1/repos"); err != nil {
			t.Fatalf("retemplateEndpoints %d: %v", i, err)
		}
	}
	eps, err := s.listEndpoints(ctx, "acme", EndpointFilter{Limit: 10})
	if err != nil {
		t.Fatalf("listEndpoints: %v", err)
	}
	if len(eps) != 1 || eps[0].RequestCount != 4 {
		t.Fatalf("repeated retemplate changed the data: %+v", eps)
	}
}

func TestRetemplatePath(t *testing.T) {
	tests := []struct {
		prefix, in, want string
		changed          bool
	}{
		{"/api/v1/repos", "/api/v1/repos/alice", "/api/v1/repos/{id}", true},
		{"/api/v1/repos", "/api/v1/repos/alice/x", "/api/v1/repos/{id}/x", true},
		{"/api/v1/repos", "/api/v1/repos/alice/x/commits", "/api/v1/repos/{id}/x/commits", true},
		// Already templated: idempotence depends on this.
		{"/api/v1/repos", "/api/v1/repos/{id}/x", "/api/v1/repos/{id}/x", false},
		// Not under the prefix.
		{"/api/v1/repos", "/api/v1/users/alice", "/api/v1/users/alice", false},
		// A longer prefix must not match a shorter sibling.
		{"/api/v1/repos", "/api/v1/reposx/alice", "/api/v1/reposx/alice", false},
		{"/api/v1/repos", "/api/v1/repos", "/api/v1/repos", false},
	}
	for _, tt := range tests {
		got, changed := retemplatePath(tt.prefix, tt.in)
		if got != tt.want || changed != tt.changed {
			t.Errorf("retemplatePath(%q, %q) = (%q, %v), want (%q, %v)",
				tt.prefix, tt.in, got, changed, tt.want, tt.changed)
		}
	}
}

// An audit covers a period, so the endpoint list has to be answerable for one.
// The filter matches on OVERLAP, not containment: an endpoint that existed
// before the period and went on existing after it was live throughout and
// belongs in the report — excluding it would understate the surface under
// review, which is the more dangerous direction of the two.
func TestPG_ListEndpoints_FiltersByPeriodOverlap(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	// Three endpoints with distinct observed lifetimes.
	seed := func(id string, first, last time.Time) {
		t.Helper()
		a := &epAgg{
			tenant: "acme", id: id, method: "GET", pathTemplate: "/" + id,
			requestCount: 1, posture: "protected", riskScore: 10,
			statusDist: map[int]int64{200: 1},
		}
		if err := s.upsertEndpoint(ctx, a); err != nil {
			t.Fatalf("upsertEndpoint %s: %v", id, err)
		}
		// Through withTenantTx, not s.db directly. api_endpoints is under RLS
		// with a fail-closed policy keyed on the app.tenant_id GUC, so a bare
		// UPDATE matches no rows and reports no error — it just silently does
		// nothing. This test used to do exactly that: the lifetimes were never
		// written, every endpoint kept its insert-time timestamps, and the
		// assertions still passed because the CI role is a superuser and
		// bypasses RLS entirely. Against a role that does not (which is what
		// production looks like) it failed, and the failure was real.
		//
		// RowsAffected is checked for the same reason: a silent zero must never
		// again look like a successful write.
		if err := s.withTenantTx(ctx, "acme", func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx,
				`UPDATE api_endpoints SET first_seen = $1, last_seen = $2
				 WHERE tenant_id = 'acme' AND id = $3`,
				first.UTC(), last.UTC(), id)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				t.Fatalf("set lifetime %s: %d rows affected, want 1 "+
					"(an RLS-blocked UPDATE reports success and changes nothing)", id, n)
			}
			return nil
		}); err != nil {
			t.Fatalf("set lifetime %s: %v", id, err)
		}
	}
	jan := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	jul := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	sep := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	dec := time.Date(2026, 12, 10, 0, 0, 0, 0, time.UTC)

	seed("before", jan, jan.AddDate(0, 1, 0)) // ended before the period
	seed("during", jul, sep)                  // inside the period
	seed("spanning", jan, dec)                // live throughout and beyond
	seed("after", dec, dec.AddDate(0, 0, 5))  // began after the period

	ids := func(f EndpointFilter) map[string]bool {
		t.Helper()
		eps, err := s.listEndpoints(ctx, "acme", f)
		if err != nil {
			t.Fatalf("listEndpoints: %v", err)
		}
		out := map[string]bool{}
		for _, e := range eps {
			out[e.ID] = true
		}
		return out
	}

	q3 := EndpointFilter{
		Limit:    50,
		SeenFrom: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		SeenTo:   time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
	}
	got := ids(q3)
	for _, want := range []string{"during", "spanning"} {
		if !got[want] {
			t.Errorf("%q missing from the period: an endpoint live during it was left out", want)
		}
	}
	for _, unwanted := range []string{"before", "after"} {
		if got[unwanted] {
			t.Errorf("%q included: its lifetime does not overlap the period", unwanted)
		}
	}

	// No window means no filtering — the previous behaviour, unchanged.
	if all := ids(EndpointFilter{Limit: 50}); len(all) != 4 {
		t.Fatalf("unbounded = %d endpoints, want all 4", len(all))
	}
	// An empty period returns nothing rather than falling back to everything.
	empty := ids(EndpointFilter{
		Limit:    50,
		SeenFrom: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		SeenTo:   time.Date(2030, 2, 1, 0, 0, 0, 0, time.UTC),
	})
	if len(empty) != 0 {
		t.Fatalf("empty period = %d endpoints, want 0 — a narrow question returned a broad answer", len(empty))
	}
}
