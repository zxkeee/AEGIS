package incident

import (
	"api-gateway/internal/secevent"
)

// Pusher is the forensic sink this one wraps. Matches store.ForensicSink
// structurally so a Sink can be installed wherever the PostgreSQL sink was.
type Pusher interface {
	Push(secevent.Entry)
}

// Sink tees security events into the correlator on their way to the forensic
// log.
//
// A wrapper rather than a second registration, because the store holds exactly
// one sink and adding fan-out there would put a slice iteration on the path of
// every blocked request for the benefit of one caller. Wrapping keeps the change
// to a single line at startup, and it makes the ordering explicit: the durable
// record is written whatever the correlator does.
//
// The normalise function is injected rather than imported so this package keeps
// depending on nothing. It turns "/orders/42" into "/orders/{id}", which is what
// makes "the same endpoint" mean the same thing here as in the catalog — the
// gateway passes discovery.NormalizePath.
type Sink struct {
	next      Pusher
	c         *Correlator
	normalise func(string) string
}

// NewSink wraps next. Either next or c may be nil.
func NewSink(c *Correlator, next Pusher, normalise func(string) string) *Sink {
	if normalise == nil {
		normalise = func(p string) string { return p }
	}
	return &Sink{next: next, c: c, normalise: normalise}
}

// Push forwards the entry and offers it to the correlator.
//
// The forward happens FIRST and unconditionally. The forensic log is the record
// of what happened; correlation is an interpretation of it. If this code ever
// panics or is misconfigured, losing the interpretation is recoverable and
// losing the record is not.
func (s *Sink) Push(e secevent.Entry) {
	if s == nil {
		return
	}
	if s.next != nil {
		s.next.Push(e)
	}
	if s.c == nil {
		return
	}
	s.c.Observe(Event{
		Tenant:   e.Tenant,
		At:       e.Timestamp,
		Reason:   e.Reason,
		IP:       e.IP,
		Consumer: consumerOf(e),
		Endpoint: endpointOf(e, s.normalise),
	})
}

// consumerOf reads the identity the middleware attached to the event, if any.
func consumerOf(e secevent.Entry) string {
	if v, ok := e.Extra["consumer"].(string); ok {
		return v
	}
	return ""
}

func endpointOf(e secevent.Entry, normalise func(string) string) string {
	if e.Path == "" {
		return ""
	}
	if e.Method == "" {
		return normalise(e.Path)
	}
	return e.Method + " " + normalise(e.Path)
}
