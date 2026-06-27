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
