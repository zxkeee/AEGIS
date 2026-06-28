package discovery

import (
	"context"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/tenant"
)

// TestPG_SpecStoreAndDrift exercises the spec storage + drift path against a
// real PostgreSQL, including per-tenant isolation of the api_specs table.
func TestPG_SpecStoreAndDrift(t *testing.T) {
	s := freshStore(t)
	ctx := context.Background()

	const doc = `
openapi: 3.0.0
paths:
  /users:
    get: {}
  /users/{id}:
    get: {}
  /legacy:
    get: {}
`
	spec, err := ParseSpec([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Store under tenant "acme".
	if err := s.upsertSpec(ctx, "acme", spec.Version, doc, spec.OpCount()); err != nil {
		t.Fatalf("upsertSpec: %v", err)
	}
	raw, meta, found, err := s.getSpec(ctx, "acme")
	if err != nil || !found {
		t.Fatalf("getSpec: found=%v err=%v", found, err)
	}
	if meta.Version != "openapi:3" || meta.OpCount != 3 || raw == "" {
		t.Fatalf("spec meta wrong: %+v", meta)
	}

	// Tenant isolation: "other" must not see acme's spec.
	if _, _, otherFound, err := s.getSpec(ctx, "other"); err != nil || otherFound {
		t.Fatalf("cross-tenant spec leak: found=%v err=%v", otherFound, err)
	}

	// Replace (upsert): a new document must overwrite, not duplicate.
	if err := s.upsertSpec(ctx, "acme", spec.Version, doc, 3); err != nil {
		t.Fatalf("upsertSpec replace: %v", err)
	}

	// End-to-end drift through the catalog read path. Seed one documented and
	// one undocumented endpoint for acme.
	mustUpsert(t, s, &epAgg{tenant: "acme", id: "GET:/users/{id}", method: "GET",
		pathTemplate: "/users/{id}", requestCount: 5, statusDist: map[int]int64{200: 5}})
	mustUpsert(t, s, &epAgg{tenant: "acme", id: "GET:/shadow", method: "GET",
		pathTemplate: "/shadow", requestCount: 2, riskScore: 40, statusDist: map[int]int64{200: 2}})

	keys, err := s.listEndpointKeys(ctx, "acme")
	if err != nil {
		t.Fatalf("listEndpointKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("listEndpointKeys = %d, want 2", len(keys))
	}
	report := ComputeDrift(spec, keys)
	if report.UndocumentedCount != 1 || report.Undocumented[0].Path != "/shadow" {
		t.Fatalf("undocumented wrong: %+v", report.Undocumented)
	}
	// /users (GET) and /legacy (GET) are documented but unobserved -> 2 zombies.
	if report.ZombieCount != 2 {
		t.Fatalf("zombie = %d, want 2", report.ZombieCount)
	}

	// Delete removes it; a second delete reports not-found.
	if ok, err := s.deleteSpec(ctx, "acme"); err != nil || !ok {
		t.Fatalf("deleteSpec: ok=%v err=%v", ok, err)
	}
	if ok, err := s.deleteSpec(ctx, "acme"); err != nil || ok {
		t.Fatalf("second deleteSpec should be not-found: ok=%v err=%v", ok, err)
	}
}

// TestPG_SpecCatalogResolution checks the Catalog spec resolution: a per-tenant
// uploaded spec overrides the config fallback.
func TestPG_SpecCatalogResolution(t *testing.T) {
	dsn := pgDSN(t)
	s := freshStore(t) // also truncates api_specs
	_ = s

	cat, err := NewCatalog(dsn, NewPostureEngine(config.GatewayConfig{}), nopLogger{})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	t.Cleanup(func() { _ = cat.Close() })

	cfgSpec, _ := ParseSpec([]byte("openapi: 3.0.0\npaths:\n  /cfg:\n    get: {}\n"))
	cat.SetConfigSpec(cfgSpec)

	acme := tenant.With(context.Background(), "acme")

	// No uploaded spec -> config fallback applies.
	if got := cat.specFor(acme); got == nil || !got.HasOp("GET", "/cfg") {
		t.Fatal("config fallback not applied for tenant without uploaded spec")
	}

	// Upload a tenant spec -> it overrides the fallback.
	if _, err := cat.SetSpec(acme, []byte("openapi: 3.0.0\npaths:\n  /acme:\n    get: {}\n")); err != nil {
		t.Fatalf("SetSpec: %v", err)
	}
	got := cat.specFor(acme)
	if got == nil || !got.HasOp("GET", "/acme") || got.HasOp("GET", "/cfg") {
		t.Fatalf("per-tenant spec did not override config fallback: %+v", got)
	}
}

func mustUpsert(t *testing.T, s *pgStore, a *epAgg) {
	t.Helper()
	if a.statusDist == nil {
		a.statusDist = map[int]int64{}
	}
	if err := s.upsertEndpoint(context.Background(), a); err != nil {
		t.Fatalf("upsertEndpoint: %v", err)
	}
}
