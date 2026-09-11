package discovery

import (
	"testing"

	"api-gateway/internal/config"
)

func TestConsumerIdentities(t *testing.T) {
	t.Run("jwt is primary", func(t *testing.T) {
		ids := consumerIdentities(Observation{ConsumerSubject: "user-7", ConsumerIP: "1.2.3.4"})
		if len(ids) != 1 || ids[0].id != "jwt:user-7" || ids[0].kind != "jwt" {
			t.Fatalf("expected single jwt identity, got %+v", ids)
		}
	})
	t.Run("jwt and key both recorded", func(t *testing.T) {
		ids := consumerIdentities(Observation{ConsumerSubject: "u", ConsumerKey: "k1"})
		if len(ids) != 2 {
			t.Fatalf("expected jwt+key, got %+v", ids)
		}
	})
	t.Run("ip only when no stronger identity", func(t *testing.T) {
		ids := consumerIdentities(Observation{ConsumerIP: "9.9.9.9"})
		if len(ids) != 1 || ids[0].kind != "ip" {
			t.Fatalf("expected ip identity, got %+v", ids)
		}
	})
	t.Run("none", func(t *testing.T) {
		if ids := consumerIdentities(Observation{}); len(ids) != 0 {
			t.Fatalf("expected no identities, got %+v", ids)
		}
	})
}

func newTestCatalog() *Catalog {
	return &Catalog{posture: NewPostureEngine(config.GatewayConfig{})}
}

func TestAggregate_FoldsCountsAndConsumers(t *testing.T) {
	c := newTestCatalog()
	eps := map[string]*epAgg{}
	cons := map[string]*consumerAgg{}
	epCons := map[[3]string]int64{}

	// Two calls to the same normalized endpoint, one a 500 error with PII, by the
	// same JWT consumer.
	c.aggregate(Observation{Tenant: "acme", Method: "GET", Path: "/users/42", Status: 200, AuthPresent: true, LatencyMs: 10, ConsumerSubject: "u"}, eps, cons, epCons)
	c.aggregate(Observation{Tenant: "acme", Method: "GET", Path: "/users/99", Status: 500, AuthPresent: true, PII: true, LatencyMs: 30, ConsumerSubject: "u"}, eps, cons, epCons)

	if len(eps) != 1 {
		t.Fatalf("expected 1 normalized endpoint, got %d", len(eps))
	}
	var a *epAgg
	for _, v := range eps {
		a = v
	}
	if a.tenant != "acme" {
		t.Fatalf("tenant not carried: %q", a.tenant)
	}
	if a.requestCount != 2 || a.errorCount != 1 || a.piiCount != 1 || a.authPresent != 2 {
		t.Fatalf("counts wrong: %+v", a)
	}
	if a.latencyMsSum != 40 || a.latencySamples != 2 {
		t.Fatalf("latency aggregation wrong: sum=%d n=%d", a.latencyMsSum, a.latencySamples)
	}
	if a.statusDist[200] != 1 || a.statusDist[500] != 1 {
		t.Fatalf("status dist wrong: %+v", a.statusDist)
	}
	if len(cons) != 1 {
		t.Fatalf("expected 1 consumer, got %d", len(cons))
	}
	if got := cons["acme\x00jwt:u"]; got == nil || got.requestCount != 2 || got.errorCount != 1 {
		t.Fatalf("consumer agg wrong: %+v", got)
	}
}

func TestAggregate_SeparatesTenants(t *testing.T) {
	// The same endpoint id observed under two tenants must aggregate separately.
	c := newTestCatalog()
	eps := map[string]*epAgg{}
	cons := map[string]*consumerAgg{}
	epCons := map[[3]string]int64{}
	c.aggregate(Observation{Tenant: "acme", Method: "GET", Path: "/x", Status: 200}, eps, cons, epCons)
	c.aggregate(Observation{Tenant: "globex", Method: "GET", Path: "/x", Status: 200}, eps, cons, epCons)
	if len(eps) != 2 {
		t.Fatalf("expected 2 tenant-scoped endpoints, got %d", len(eps))
	}
}

func TestAggregate_AnonCounted(t *testing.T) {
	c := newTestCatalog()
	eps := map[string]*epAgg{}
	c.aggregate(Observation{Method: "GET", Path: "/x", Status: 200, AuthPresent: false},
		eps, map[string]*consumerAgg{}, map[[3]string]int64{})
	for _, a := range eps {
		if a.anonCount != 1 || a.authPresent != 0 {
			t.Fatalf("anon not counted: %+v", a)
		}
	}
}

func TestRecord_DropsInvalidEnqueuesValid(t *testing.T) {
	c := &Catalog{posture: NewPostureEngine(config.GatewayConfig{}), ch: make(chan Observation, 4)}

	c.Record(Observation{})              // missing method+path → dropped
	c.Record(Observation{Method: "GET"}) // missing path → dropped
	if len(c.ch) != 0 {
		t.Fatalf("invalid observations were enqueued: %d", len(c.ch))
	}

	c.Record(Observation{Method: "GET", Path: "/ok"})
	if len(c.ch) != 1 {
		t.Fatalf("valid observation not enqueued: %d", len(c.ch))
	}
}

func TestRecord_NonBlockingOnFullBuffer(t *testing.T) {
	c := &Catalog{posture: NewPostureEngine(config.GatewayConfig{}), ch: make(chan Observation, 1)}
	c.Record(Observation{Method: "GET", Path: "/a"})
	// Buffer is now full; this must not block or panic — it drops.
	done := make(chan struct{})
	go func() {
		c.Record(Observation{Method: "GET", Path: "/b"})
		close(done)
	}()
	<-done
	if len(c.ch) != 1 {
		t.Fatalf("buffer should still hold exactly 1, got %d", len(c.ch))
	}
}

func TestSetPostureEngine_Swaps(t *testing.T) {
	c := newTestCatalog()
	first := c.engine()
	c.SetPostureEngine(NewPostureEngine(config.GatewayConfig{}))
	if c.engine() == first {
		t.Fatal("posture engine was not swapped")
	}
}

// The catalog caps the total number of distinct endpoints so a path-flood
// through a catch-all route cannot grow api_endpoints without bound. New
// endpoints past the cap are dropped; endpoints already known keep aggregating.
func TestAggregate_CardinalityCap(t *testing.T) {
	c := &Catalog{
		posture:      NewPostureEngine(config.GatewayConfig{}),
		seen:         map[string]struct{}{},
		maxEndpoints: 3, // tiny cap for the test
	}
	eps := map[string]*epAgg{}
	cons := map[string]*consumerAgg{}
	epCons := map[[3]string]int64{}

	// Ten distinct alphabetic paths (which NormalizePath does NOT collapse).
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i", "/j"} {
		c.aggregate(Observation{Method: "GET", Path: p, Status: 200}, eps, cons, epCons)
	}
	if len(eps) != 3 {
		t.Fatalf("cardinality cap not enforced: cataloged %d endpoints, want 3", len(eps))
	}
	if len(c.seen) != 3 {
		t.Fatalf("seen set = %d, want 3", len(c.seen))
	}

	// A known endpoint (already in the window) still aggregates past the cap.
	c.aggregate(Observation{Method: "GET", Path: "/a", Status: 200}, eps, cons, epCons)
	var aReqs int64
	for k, v := range eps {
		if k == tenantDefaultKey("GET /a") {
			aReqs = v.requestCount
		}
	}
	if aReqs != 2 {
		t.Fatalf("known endpoint stopped aggregating after cap: /a reqs=%d, want 2", aReqs)
	}
}

func tenantDefaultKey(id string) string { return "default\x00" + id }

// maxEndpoints == 0 means "unlimited" so a zero-value / struct-literal Catalog
// (used across the aggregate unit tests) never drops endpoints.
func TestAggregate_ZeroCapIsUnlimited(t *testing.T) {
	c := newTestCatalog() // maxEndpoints == 0
	eps := map[string]*epAgg{}
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e"} {
		c.aggregate(Observation{Method: "GET", Path: p, Status: 200}, eps, map[string]*consumerAgg{}, map[[3]string]int64{})
	}
	if len(eps) != 5 {
		t.Fatalf("zero cap must not drop endpoints; got %d want 5", len(eps))
	}
}

// A mirrored observation has no response, and the catalog must say so rather
// than record zeros that read like findings.
//
// This is the honesty requirement of mirror-sink mode. A PII count of zero
// means "no sensitive data was found" for a proxied request and "responses were
// never looked at" for a mirrored one. If both produce the same row, an auditor
// shown that catalog is told the endpoint is clean when nobody checked.
func TestAggregate_MirroredObservationRecordsNoResponseFacts(t *testing.T) {
	c := newTestCatalog()
	eps := map[string]*epAgg{}
	cons := map[string]*consumerAgg{}
	epCons := map[[3]string]int64{}

	// The response-side fields are set deliberately, to prove they are IGNORED
	// rather than merely absent.
	c.aggregate(Observation{
		Tenant: "acme", Method: "GET", Path: "/customers/7", ConsumerIP: "1.2.3.4",
		RequestOnly: true,
		Status:      200, LatencyMs: 42, PII: true, PIITypes: []string{"credit_card"},
	}, eps, cons, epCons)

	if len(eps) != 1 {
		t.Fatalf("endpoints recorded = %d, want 1", len(eps))
	}
	var a *epAgg
	for _, v := range eps {
		a = v
	}

	if a.requestCount != 1 {
		t.Errorf("requestCount = %d, want 1: the REQUEST was observed", a.requestCount)
	}
	if a.responsesSeen != 0 {
		t.Errorf("responsesSeen = %d, want 0: there was no response to see", a.responsesSeen)
	}
	if a.piiCount != 0 {
		t.Errorf("piiCount = %d, want 0: a mirrored request carries no response body, "+
			"so a PII signal on it is not an observation", a.piiCount)
	}
	if len(a.piiTypes) != 0 {
		t.Errorf("piiTypes = %v, want empty", a.piiTypes)
	}
	if a.latencySamples != 0 || a.latencyMsSum != 0 {
		t.Errorf("latency recorded (%d samples, %d ms); nothing was timed",
			a.latencySamples, a.latencyMsSum)
	}
	if len(a.statusDist) != 0 {
		t.Errorf("statusDist = %v, want empty: the sink's own 204 is not the caller's status",
			a.statusDist)
	}
	if a.errorCount != 0 {
		t.Errorf("errorCount = %d, want 0", a.errorCount)
	}
	// The request-side half IS recorded — that is the point of the mode.
	if a.anonCount != 1 {
		t.Errorf("anonCount = %d, want 1: the request carried no identity", a.anonCount)
	}
}

// The same observation proxied normally records everything, so the test above
// pins RequestOnly and not an unrelated gap.
func TestAggregate_ProxiedObservationRecordsResponseFacts(t *testing.T) {
	c := newTestCatalog()
	eps := map[string]*epAgg{}

	c.aggregate(Observation{
		Tenant: "acme", Method: "GET", Path: "/customers/7", ConsumerIP: "1.2.3.4",
		Status: 200, LatencyMs: 42, PII: true, PIITypes: []string{"credit_card"},
	}, eps, map[string]*consumerAgg{}, map[[3]string]int64{})

	var a *epAgg
	for _, v := range eps {
		a = v
	}
	if a.responsesSeen != 1 || a.piiCount != 1 || a.latencySamples != 1 {
		t.Fatalf("proxied observation lost response facts: responsesSeen=%d piiCount=%d "+
			"latencySamples=%d", a.responsesSeen, a.piiCount, a.latencySamples)
	}
}
