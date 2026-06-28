package discovery

import "testing"

func mustSpec(t *testing.T, doc string) *Spec {
	t.Helper()
	s, err := ParseSpec([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

const driftSpec = `
openapi: 3.0.0
paths:
  /users:
    get: {}
    post: {}
  /users/{id}:
    get: {}
  /legacy:
    get: {}
`

func TestComputeDrift_Categories(t *testing.T) {
	spec := mustSpec(t, driftSpec)
	eps := []Endpoint{
		{Method: "GET", PathTemplate: "/users"},                        // documented
		{Method: "POST", PathTemplate: "/users"},                       // documented
		{Method: "GET", PathTemplate: "/users/{id}"},                   // documented
		{Method: "DELETE", PathTemplate: "/users/{id}", RiskScore: 80}, // undocumented method on known path
		{Method: "GET", PathTemplate: "/admin/secret", RiskScore: 50},  // wholly undocumented (shadow)
	}
	r := ComputeDrift(spec, eps)

	if !r.SpecPresent || r.DocumentedCount != 4 || r.ObservedCount != 5 {
		t.Fatalf("summary wrong: %+v", r)
	}
	if r.UndocumentedCount != 2 {
		t.Fatalf("undocumented = %d, want 2", r.UndocumentedCount)
	}
	// Sorted by risk desc: DELETE /users/{id} (80) before GET /admin/secret (50).
	if r.Undocumented[0].Path != "/users/{id}" || !r.Undocumented[0].PathDocumented {
		t.Errorf("first undocumented wrong: %+v", r.Undocumented[0])
	}
	if r.Undocumented[1].Path != "/admin/secret" || r.Undocumented[1].PathDocumented {
		t.Errorf("second undocumented wrong: %+v", r.Undocumented[1])
	}
	// /legacy GET is documented but never observed -> zombie.
	if r.ZombieCount != 1 || r.Zombie[0].Path != "/legacy" || r.Zombie[0].Method != "GET" {
		t.Errorf("zombie wrong: %+v", r.Zombie)
	}
}

func TestComputeDrift_NilSpec(t *testing.T) {
	r := ComputeDrift(nil, []Endpoint{{Method: "GET", PathTemplate: "/x"}})
	if r.SpecPresent {
		t.Error("nil spec must report SpecPresent=false")
	}
	if r.UndocumentedCount != 0 || r.ZombieCount != 0 {
		t.Error("nil spec must produce no drift (not flag everything undocumented)")
	}
	// Slices are non-nil for stable JSON ([] not null).
	if r.Undocumented == nil || r.Zombie == nil {
		t.Error("drift slices should be non-nil")
	}
}

func TestComputeDrift_FullyDocumented(t *testing.T) {
	spec := mustSpec(t, "openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n")
	r := ComputeDrift(spec, []Endpoint{{Method: "GET", PathTemplate: "/a"}})
	if r.UndocumentedCount != 0 || r.ZombieCount != 0 {
		t.Errorf("expected no drift, got %+v", r)
	}
}

func TestDriftFinding(t *testing.T) {
	spec := mustSpec(t, driftSpec)

	// Documented op -> no finding.
	if _, ok := driftFinding(Endpoint{Method: "GET", PathTemplate: "/users"}, spec); ok {
		t.Error("documented endpoint should not produce a drift finding")
	}
	// Undocumented method on a known path.
	f, ok := driftFinding(Endpoint{Method: "DELETE", PathTemplate: "/users/{id}"}, spec)
	if !ok || f.Code != "undocumented_method" || f.OWASP != "API9:2023" {
		t.Errorf("undocumented_method finding wrong: %+v ok=%v", f, ok)
	}
	// Wholly undocumented path.
	f, ok = driftFinding(Endpoint{Method: "GET", PathTemplate: "/admin/secret"}, spec)
	if !ok || f.Code != "undocumented_endpoint" {
		t.Errorf("undocumented_endpoint finding wrong: %+v ok=%v", f, ok)
	}
	// Nil spec -> no finding.
	if _, ok := driftFinding(Endpoint{Method: "GET", PathTemplate: "/x"}, nil); ok {
		t.Error("nil spec should not produce findings")
	}
}
