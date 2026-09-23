package ticket

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Register is the half of the incident store this worker needs.
//
// An interface rather than *incident.PGStore, because this package must not
// import the register's schema to be testable, and because the seam is where
// the fake goes.
type Register interface {
	// Unticketed lists incidents at or above minSeverity with no ticket.
	Unticketed(ctx context.Context, tenant, minSeverity string, limit int) ([]Incident, error)
	// RecordTicket stores a reference. It must return ErrAlreadyRecorded when
	// one is already there, so a race is detectable rather than silent.
	RecordTicket(ctx context.Context, tenant, incidentID, system, ref, url string) error
	// Tenants lists the tenants with incidents to consider.
	Tenants(ctx context.Context) ([]string, error)
}

// ErrAlreadyRecorded is what Register.RecordTicket returns when this incident
// already has a ticket. Defined here so the Register implementation and this
// package agree without one importing the other.
var ErrAlreadyRecorded = errors.New("ticket: already recorded")

// Logger is the subset of the gateway logger used here.
//
// Variadic fields, matching *logger.Logger's own signature, so the real logger
// satisfies this without an adapter. A narrower interface would have read
// better and would have needed a wrapper at every call site, which is a worse
// trade than one ellipsis.
type Logger interface {
	Info(msg string, fields ...map[string]any)
	Error(msg string, fields ...map[string]any)
}

// Worker files unticketed incidents on an interval.
//
// A poller rather than a callback on incident creation, and that is a
// deliberate trade. A callback would file sooner; it would also put a network
// call to a third party inside the transaction that records the incident, where
// a slow tracker becomes a slow gateway and a failed call becomes a lost
// incident. Polling means a ticket appears within one interval instead of
// instantly, and means a tracker outage costs nothing but a delay: the next
// sweep picks up everything it missed, because "has no ticket" is a question
// about the database and not about what happened during the outage.
type Worker struct {
	client   *Client
	reg      Register
	log      Logger
	interval time.Duration
	minSev   string
	batch    int

	quit      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewWorker builds the filing worker. interval of 0 means one minute.
func NewWorker(c *Client, reg Register, log Logger, interval time.Duration, minSeverity string, batch int) *Worker {
	if interval <= 0 {
		interval = time.Minute
	}
	if batch <= 0 {
		batch = 20
	}
	if minSeverity == "" {
		minSeverity = "major"
	}
	return &Worker{
		client: c, reg: reg, log: log,
		interval: interval, minSev: minSeverity, batch: batch,
		quit: make(chan struct{}),
	}
}

// Start runs the worker until Close.
func (w *Worker) Start() {
	if w == nil || w.client == nil || w.reg == nil {
		return
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		t := time.NewTicker(w.interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				w.Sweep(context.Background())
			case <-w.quit:
				return
			}
		}
	}()
}

// Close stops the worker.
func (w *Worker) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() { close(w.quit) })
	w.wg.Wait()
	return nil
}

// Sweep files every eligible incident once. Exported so a test drives it
// directly rather than waiting for a tick, and so an operator-triggered run can
// exist later without a second code path.
func (w *Worker) Sweep(ctx context.Context) {
	if w == nil || w.client == nil || w.reg == nil {
		return
	}
	tenants, err := w.reg.Tenants(ctx)
	if err != nil {
		w.log.Error("ticket: cannot list tenants", map[string]any{"error": err.Error()})
		return
	}
	for _, tenant := range tenants {
		w.sweepTenant(ctx, tenant)
	}
}

func (w *Worker) sweepTenant(ctx context.Context, tenant string) {
	pending, err := w.reg.Unticketed(ctx, tenant, w.minSev, w.batch)
	if err != nil {
		w.log.Error("ticket: cannot list unticketed incidents", map[string]any{
			"tenant": tenant, "error": err.Error(),
		})
		return
	}
	for _, inc := range pending {
		inc.Tenant = tenant
		filed, err := w.client.File(ctx, inc)
		if err != nil {
			// Logged and left unticketed. The next sweep retries it, which is
			// the whole reason this is a poller: a tracker outage delays
			// filing and never drops it.
			w.log.Error("ticket: filing failed", map[string]any{
				"tenant": tenant, "incident": inc.ID, "system": w.client.System(),
				"error": err.Error(),
			})
			continue
		}
		if filed.SearchFailed {
			w.log.Error("ticket: filed without a duplicate check", map[string]any{
				"tenant": tenant, "incident": inc.ID, "ref": filed.Ref,
				"detail": "the tracker search failed, so this may be a second ticket for one incident",
			})
		}

		err = w.reg.RecordTicket(ctx, tenant, inc.ID, w.client.System(), filed.Ref, filed.URL)
		switch {
		case err == nil:
			w.log.Info("ticket: filed", map[string]any{
				"tenant": tenant, "incident": inc.ID,
				"system": w.client.System(), "ref": filed.Ref, "adopted": filed.Adopted,
			})
		case errors.Is(err, ErrAlreadyRecorded):
			// Another gateway won the race. Both created a ticket; only one
			// reference is stored. Say so with both references, because the
			// duplicate is real and somebody has to close it — swallowing this
			// would leave an orphan ticket nobody can trace back.
			w.log.Error("ticket: lost a filing race; this ticket is a duplicate", map[string]any{
				"tenant": tenant, "incident": inc.ID,
				"system": w.client.System(), "orphan_ref": filed.Ref,
			})
		default:
			// The ticket exists remotely and is not recorded here. The next
			// sweep will find the incident unticketed again and adopt the
			// ticket by its correlation key rather than create a second one —
			// which is exactly the case the search in File exists for.
			w.log.Error("ticket: filed but not recorded", map[string]any{
				"tenant": tenant, "incident": inc.ID, "ref": filed.Ref,
				"error": err.Error(),
			})
		}
	}
}
