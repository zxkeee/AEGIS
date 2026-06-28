package discovery

import (
	"context"
	"os"
	"testing"
	"time"

	"api-gateway/internal/config"
)

// pgDSN returns the test PostgreSQL DSN or skips when unset (local runs without
// a database). CI provides POSTGRES_DSN via the postgres service.
func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set; skipping PostgreSQL integration test")
	}
	return dsn
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
