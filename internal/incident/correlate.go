package incident

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Event is one security event offered to the correlator.
//
// A deliberately small struct rather than the forensic entry itself, so this
// package depends on nothing and can be driven from a test with three lines.
type Event struct {
	Tenant   string
	At       time.Time
	Reason   string
	IP       string
	Consumer string
	// Endpoint is the normalised "METHOD /path/{id}" the event was aimed at.
	Endpoint string
}

// ClassOf maps an event reason to the incident class it belongs to, or "" for
// an event that must not open an incident.
//
// The exclusions matter more than the inclusions. A rate-limit rejection, a
// redacted response, a blocked address already on a blocklist — these are
// controls working as designed, thousands of times a day. An incident list that
// fills up with them is not merely noisy, it is worse than no list at all,
// because it teaches the operator to stop looking, and the one incident that
// needed a 24-hour early warning is in there somewhere.
//
// What is here is activity a regulator would recognise as an attack on the
// service: authorization abuse, application attacks, a caller behaving in a way
// the behaviour model scores as hostile, and traffic from a known-bad source.
func ClassOf(reason string) string {
	switch {
	case strings.HasPrefix(reason, "bola"):
		return "bola"
	case strings.HasPrefix(reason, "bfla"):
		return "bfla"
	case strings.HasPrefix(reason, "waf"):
		return "waf"
	case strings.HasPrefix(reason, "behavior"):
		return "behavior"
	case strings.HasPrefix(reason, "threat"):
		return "threat"
	default:
		return ""
	}
}

// subjectOf identifies who the activity came from. A verified consumer beats a
// source address: addresses rotate, and correlating on one splits a single
// campaign into hundreds of incidents.
func subjectOf(e Event) string {
	if e.Consumer != "" {
		return e.Consumer
	}
	return e.IP
}

// key identifies one incident stream: the tenant, what kind of activity it is,
// and who it came from. Separate from Delta because Delta carries slices and a
// map key must be comparable.
type key struct{ tenant, class, subject string }

// Delta is the accumulated effect of one flush interval on one incident key.
type Delta struct {
	Tenant, Class, Subject string
	First, Last            time.Time
	Count                  int
	Endpoints              []string
	Sources                []string
	Reasons                []string
}

// Store persists correlated deltas.
type Store interface {
	// Merge folds d into the open incident for its key whose last event falls
	// within window, opening a new incident when there is none.
	Merge(ctx context.Context, d Delta, window time.Duration) error
}

// Logger is the minimal logging surface this package needs.
type Logger interface {
	Error(msg string, fields ...map[string]any)
}

// Defaults for the correlator.
const (
	// DefaultWindow is how long an incident stays open to new events of the
	// same key. Beyond it the activity is a new incident, because a report
	// covering a fortnight of unrelated attempts describes nothing.
	DefaultWindow = 6 * time.Hour
	// DefaultFlush is how often accumulated deltas are written.
	DefaultFlush = 5 * time.Second
	// maxList caps each attacker-influenced list on an incident.
	maxList = 50
	// queueSize bounds the ingest buffer. Full means drop: an incident record
	// is valuable, but not more valuable than serving traffic.
	queueSize = 4096
)

// Correlator groups events into incidents.
//
// Observe never blocks and never touches the database: it drops the event into
// a buffer, a worker aggregates by key over a flush interval, and only then does
// one write per key reach PostgreSQL. That shape is not premature optimisation —
// an object-enumeration attack is a few hundred events a second by definition,
// and one INSERT per event would make the incident recorder the slowest part of
// handling the attack it is recording.
type Correlator struct {
	store  Store
	log    Logger
	window time.Duration
	flush  time.Duration

	ch   chan Event
	quit chan struct{}
	wg   sync.WaitGroup

	// flushReq asks the worker to write what it holds and close the channel it
	// carries. Tests need a deterministic flush; a sleep long enough to be
	// reliable is also long enough to make the suite unbearable.
	flushReq chan chan struct{}
}

// New starts a correlator. Close it to stop the worker and flush.
func New(s Store, log Logger) *Correlator {
	c := &Correlator{
		store: s, log: log,
		window: DefaultWindow, flush: DefaultFlush,
		ch:       make(chan Event, queueSize),
		quit:     make(chan struct{}),
		flushReq: make(chan chan struct{}),
	}
	c.wg.Add(1)
	go c.run()
	return c
}

// Observe offers an event. It never blocks. Events that cannot open an incident
// (see ClassOf) are discarded here, before they cost a buffer slot.
func (c *Correlator) Observe(e Event) {
	if c == nil || ClassOf(e.Reason) == "" {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	select {
	case c.ch <- e:
	default:
		// Buffer full. Losing the event is bad; blocking the request that
		// produced it is worse, and a flood is exactly when this fills up.
	}
}

// Flush writes everything held so far and waits for it.
func (c *Correlator) Flush() {
	if c == nil {
		return
	}
	done := make(chan struct{})
	select {
	case c.flushReq <- done:
		<-done
	case <-c.quit:
	}
}

// Close stops the worker after a final flush.
func (c *Correlator) Close() error {
	if c == nil {
		return nil
	}
	close(c.quit)
	c.wg.Wait()
	return nil
}

type aggregate struct {
	first, last time.Time
	count       int
	endpoints   []string
	sources     []string
	reasons     []string
}

func (c *Correlator) run() {
	defer c.wg.Done()
	t := time.NewTicker(c.flush)
	defer t.Stop()

	pending := map[key]*aggregate{}
	for {
		select {
		case e := <-c.ch:
			c.accumulate(pending, e)
		case <-t.C:
			c.write(pending)
			pending = map[key]*aggregate{}
		case done := <-c.flushReq:
			// Drain what is already queued so a caller that just observed an
			// event and then flushed sees it persisted.
			for {
				select {
				case e := <-c.ch:
					c.accumulate(pending, e)
					continue
				default:
				}
				break
			}
			c.write(pending)
			pending = map[key]*aggregate{}
			close(done)
		case <-c.quit:
			for {
				select {
				case e := <-c.ch:
					c.accumulate(pending, e)
					continue
				default:
				}
				break
			}
			c.write(pending)
			return
		}
	}
}

// accumulate folds one event into the pending map. The map key carries only the
// identity fields, so the aggregate is per (tenant, class, subject).
func (c *Correlator) accumulate(pending map[key]*aggregate, e Event) {
	k := key{tenant: e.Tenant, class: ClassOf(e.Reason), subject: subjectOf(e)}
	a := pending[k]
	if a == nil {
		a = &aggregate{first: e.At, last: e.At}
		pending[k] = a
	}
	if e.At.Before(a.first) {
		a.first = e.At
	}
	if e.At.After(a.last) {
		a.last = e.At
	}
	a.count++
	// Bounded here as well as in sortedUnique, so a flood cannot grow these
	// slices without limit between two flushes.
	if len(a.endpoints) < maxList*4 {
		a.endpoints = append(a.endpoints, e.Endpoint)
	}
	if len(a.sources) < maxList*4 {
		a.sources = append(a.sources, e.IP)
	}
	if len(a.reasons) < maxList*4 {
		a.reasons = append(a.reasons, e.Reason)
	}
}

func (c *Correlator) write(pending map[key]*aggregate) {
	if len(pending) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for k, a := range pending {
		d := Delta{
			Tenant: k.tenant, Class: k.class, Subject: k.subject,
			First: a.first, Last: a.last, Count: a.count,
		}
		d.Endpoints = sortedUnique(a.endpoints, maxList)
		d.Sources = sortedUnique(a.sources, maxList)
		d.Reasons = sortedUnique(a.reasons, maxList)
		if err := c.store.Merge(ctx, d, c.window); err != nil && c.log != nil {
			c.log.Error("incident: merge failed", map[string]any{
				"error": err.Error(), "class": d.Class, "subject": d.Subject,
			})
		}
	}
}
