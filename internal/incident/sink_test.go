package incident

import (
	"strings"
	"sync"
	"testing"

	"api-gateway/internal/secevent"
)

type recordingPusher struct {
	mu sync.Mutex
	in []secevent.Entry
}

func (r *recordingPusher) Push(e secevent.Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.in = append(r.in, e)
}

func (r *recordingPusher) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.in)
}

// fakeNormalise stands in for discovery.NormalizePath.
func fakeNormalise(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if s != "" && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func TestSink_ForwardsAndCorrelates(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	next := &recordingPusher{}
	s := NewSink(c, next, fakeNormalise)

	s.Push(secevent.Entry{
		Tenant: "acme", Timestamp: t0, Reason: "bola_object_ownership",
		IP: "1.2.3.4", Path: "/orders/42", Method: "GET",
		Extra: map[string]any{"consumer": "jwt:alice"},
	})
	_ = c.Close()

	if next.count() != 1 {
		t.Fatalf("the durable record got %d entries, want 1", next.count())
	}
	got := fs.all()
	if len(got) != 1 {
		t.Fatalf("%d merges, want 1", len(got))
	}
	if got[0].Subject != "jwt:alice" {
		t.Errorf("subject = %q, want the consumer from Extra", got[0].Subject)
	}
	// Normalised, so "the same endpoint" means the same thing here as in the
	// catalog — otherwise every object id opens its own endpoint entry.
	if len(got[0].Endpoints) != 1 || got[0].Endpoints[0] != "GET /orders/{id}" {
		t.Errorf("endpoints = %v, want the normalised template", got[0].Endpoints)
	}
}

// Two ids on one endpoint are one endpoint. Without normalisation an
// enumeration attack — which is a different id every request, by definition —
// would fill the incident's endpoint list with hundreds of entries.
func TestSink_NormalisesSoEnumerationIsOneEndpoint(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	s := NewSink(c, nil, fakeNormalise)

	for i := 0; i < 30; i++ {
		s.Push(secevent.Entry{
			Tenant: "acme", Timestamp: t0, Reason: "bola_x", IP: "1.2.3.4",
			Method: "GET", Path: "/orders/" + string(rune('0'+i%10)),
			Extra: map[string]any{"consumer": "jwt:alice"},
		})
	}
	_ = c.Close()

	got := fs.all()
	if len(got) != 1 {
		t.Fatalf("%d merges, want 1", len(got))
	}
	if len(got[0].Endpoints) != 1 {
		t.Errorf("endpoints = %v, want one normalised template", got[0].Endpoints)
	}
}

// The forensic log is the record; correlation is an interpretation of it.
// Losing the interpretation is recoverable, losing the record is not — so the
// forward must not depend on the correlator existing.
func TestSink_ForwardsEvenWithNoCorrelator(t *testing.T) {
	next := &recordingPusher{}
	s := NewSink(nil, next, nil)
	s.Push(secevent.Entry{Tenant: "acme", Reason: "bola_x", Path: "/x"})
	if next.count() != 1 {
		t.Fatalf("the durable record got %d entries, want 1", next.count())
	}
}

func TestSink_NilSafe(t *testing.T) {
	var s *Sink
	s.Push(secevent.Entry{Reason: "bola_x"}) // must not panic
	// No next sink and no correlator is a valid, if useless, configuration.
	NewSink(nil, nil, nil).Push(secevent.Entry{Reason: "bola_x"})
}

func TestSink_EventWithoutIdentityOrPath(t *testing.T) {
	fs := &fakeStore{}
	c := New(fs, nopLog{})
	s := NewSink(c, nil, fakeNormalise)
	s.Push(secevent.Entry{Tenant: "acme", Timestamp: t0, Reason: "waf_blocked", IP: "9.9.9.9"})
	_ = c.Close()

	got := fs.all()
	if len(got) != 1 {
		t.Fatalf("%d merges, want 1", len(got))
	}
	if got[0].Subject != "9.9.9.9" {
		t.Errorf("subject = %q, want the source address as the fallback", got[0].Subject)
	}
	if len(got[0].Endpoints) != 0 {
		t.Errorf("endpoints = %v, want none for an event with no path", got[0].Endpoints)
	}
}
