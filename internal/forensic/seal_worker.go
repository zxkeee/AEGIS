package forensic

import (
	"context"
	"errors"
	"time"
)

// SealWorker seals closed periods on a schedule.
//
// It walks forward from the last sealed period, so a gateway that was down for
// a day catches up on restart rather than leaving a hole. A hole matters: an
// unsealed window is one an operator can edit freely, and "there is no seal for
// Tuesday" is indistinguishable from "the seal for Tuesday was deleted" unless
// the chain is contiguous.
type SealWorker struct {
	sink    *PGSink
	cfg     SealSchedule
	signer  Signer
	tenants func(context.Context) ([]string, error)
	log     Logger
	quit    chan struct{}
}

// SealSchedule is the timing half of the configuration, kept here so this
// package does not import internal/config.
type SealSchedule struct {
	Period time.Duration
	Lag    time.Duration
}

// NewSealWorker builds the worker. tenants enumerates which tenants to seal —
// every tenant with entries, not only the ones currently configured, because a
// tenant removed from the config still has a log somebody may audit.
func NewSealWorker(sink *PGSink, cfg SealSchedule, signer Signer,
	tenants func(context.Context) ([]string, error), log Logger) *SealWorker {
	if cfg.Period <= 0 {
		cfg.Period = time.Hour
	}
	if cfg.Lag <= 0 {
		cfg.Lag = 5 * time.Minute
	}
	return &SealWorker{sink: sink, cfg: cfg, signer: signer, tenants: tenants, log: log,
		quit: make(chan struct{})}
}

// Run seals on every tick until ctx is done. It never returns an error: a
// failed seal is logged and retried next tick, because a transient database
// problem must not take the gateway down.
func (w *SealWorker) Run(ctx context.Context) {
	w.sealDue(ctx, time.Now())
	t := time.NewTicker(w.cfg.Period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.quit:
			return
		case now := <-t.C:
			w.sealDue(ctx, now)
		}
	}
}

// Stop ends the worker.
func (w *SealWorker) Stop() { close(w.quit) }

// maxCatchUpPeriods bounds one tick's work. A gateway down for a month would
// otherwise try to seal 720 hourly periods in one pass, holding a transaction
// per period while the request path waits on the same pool. It catches up over
// several ticks instead.
const maxCatchUpPeriods = 24

func (w *SealWorker) sealDue(ctx context.Context, now time.Time) {
	tenants, err := w.tenants(ctx)
	if err != nil {
		w.log.Error("forensic: seal worker could not list tenants", map[string]any{"error": err.Error()})
		return
	}
	// Everything up to this instant is old enough that the sink has finished
	// writing it. Periods after it are still open.
	cutoff := now.Add(-w.cfg.Lag).Truncate(w.cfg.Period)

	for _, tenant := range tenants {
		from, err := w.sink.nextUnsealedPeriod(ctx, tenant, w.cfg.Period)
		if err != nil {
			w.log.Error("forensic: seal worker could not find the next period",
				map[string]any{"error": err.Error(), "tenant": tenant})
			continue
		}
		if from.IsZero() {
			continue // no entries yet: nothing to commit to
		}
		for n := 0; n < maxCatchUpPeriods && from.Before(cutoff); n++ {
			to := from.Add(w.cfg.Period)
			seal, err := w.sink.SealPeriod(ctx, tenant, from, to, w.signer)
			switch {
			case errors.Is(err, ErrPeriodAlreadySealed):
				// Another replica got there first. Expected under HA, not an error.
			case err != nil:
				w.log.Error("forensic: seal failed", map[string]any{
					"error": err.Error(), "tenant": tenant, "period_start": from,
				})
				// Stop this tenant here rather than skipping the period: sealing
				// the NEXT one would leave a permanent gap in the chain, and a
				// gap is what the chain exists to make impossible.
				n = maxCatchUpPeriods
				continue
			default:
				w.log.Info("forensic: period sealed", map[string]any{
					"tenant": tenant, "period_start": from, "entries": seal.EntryCount,
					"root": short(seal.MerkleRoot),
				})
			}
			from = to
		}
	}
}
