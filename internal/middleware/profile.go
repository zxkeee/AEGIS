package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"api-gateway/internal/alert"
	"api-gateway/internal/config"
)

// Per-consumer behavioural profiling — the honest answer to "do you do anomaly
// detection".
//
// # Why this and not a model
//
// The question a security team asks is whether AEGIS notices a consumer
// behaving unlike itself. A trained model is the expected answer and the wrong
// one to build first: it needs labelled traffic that does not exist before a
// customer does, it cannot explain a finding, and an unexplainable finding in
// this domain is worse than none. The measured evidence for that is in this
// project's own history — a false-positive assessment produced 101 identical
// "critical" findings out of 161 requests, and what made them worthless was not
// the count but that none of them said why.
//
// So: each consumer is compared against ITS OWN established norm, on
// dimensions a stream of requests establishes online. No training set, no
// model, no labels. Every finding names the dimension, the observed value and
// the norm it departed from, in one sentence an operator can act on or dismiss.
//
// # The dimensions, and why these
//
//   - VOLUME — requests in the window. The crudest signal and the one that
//     catches a stolen credential being used by a script.
//   - AUTH FAILURES — 401/403 in the window. A consumer that suddenly cannot
//     authorise is either broken or probing, and both are worth a look. This is
//     the credential-stuffing and privilege-probing shape.
//   - NOT FOUND — 404 in the window. Path enumeration against a consumer that
//     normally knows exactly which endpoints it calls.
//   - ENDPOINT SPREAD — distinct endpoints touched. A client with a fixed
//     integration touches a fixed set; a sudden widening is either a deploy or
//     someone exploring with a valid token.
//
// Each is compared independently, because a finding that says "anomaly score
// 0.87" tells an operator nothing and "this consumer's 403 rate is 12× its own
// norm" tells them what to look at.
//
// # What it deliberately does not do
//
//   - IT NEVER BLOCKS. A statistical departure is not proof of anything, and
//     blocking on one is how a customer's nightly batch job gets cut off at
//     02:00. Findings are recorded and alerted; enforcement stays with the
//     controls that have a deterministic reason to act.
//   - It does not learn from an anomalous window. An attack that persists would
//     otherwise become the new normal — the guard the BOLA baseline already
//     needed.
//   - It says nothing about a consumer it has not seen enough of. Below the
//     floor there is no norm to depart from, only noise to report.

// profileMetric is one dimension of the profile.
type profileMetric struct {
	name string
	// why renders the finding for a human, given the observed value and norm.
	why func(cur int64, base float64) string
}

var (
	metricVolume = profileMetric{
		name: "volume",
		why: func(cur int64, base float64) string {
			return fmt.Sprintf("made %d requests in this window against a norm of %.1f", cur, base)
		},
	}
	metricAuthFail = profileMetric{
		name: "auth_failures",
		why: func(cur int64, base float64) string {
			return fmt.Sprintf("saw %d authorisation failures (401/403) against a norm of %.1f — "+
				"either a broken client or someone probing what a valid token reaches", cur, base)
		},
	}
	metricNotFound = profileMetric{
		name: "not_found",
		why: func(cur int64, base float64) string {
			return fmt.Sprintf("hit %d missing paths against a norm of %.1f — path enumeration "+
				"looks like this from a consumer that normally knows its endpoints", cur, base)
		},
	}
	metricEndpoints = profileMetric{
		name: "endpoint_spread",
		why: func(cur int64, base float64) string {
			return fmt.Sprintf("touched %d distinct endpoints against a norm of %.1f — a fixed "+
				"integration widening its reach is either a deploy or exploration", cur, base)
		},
	}
)

// profileStore is what this middleware needs from the store.
type profileStore interface {
	IncrProfileWindow(ctx context.Context, consumer, metric string, window time.Duration) (int64, error)
	TrackProfileDistinct(ctx context.Context, consumer, metric, value string, window time.Duration) (int64, error)
	TrackProfileBaseline(ctx context.Context, consumer, metric string, current int64, learn bool, ttl time.Duration) (float64, error)
}

// profiler holds the settled configuration so the request path reads as four
// observations rather than as one long closure.
type profiler struct {
	st          profileStore
	log         Logger
	al          *Alerter
	window      time.Duration
	baselineTTL time.Duration
	sensitivity float64
	floor       int
	allow       map[string]bool
}

// observe compares one dimension against the consumer's own norm and reports a
// departure. Errors are swallowed on purpose: a profile is an observation, and
// a store outage must turn into neither a blocked request nor an invented
// finding.
func (p *profiler) observe(ctx context.Context, consumer, endpoint string, m profileMetric, cur int64, err error) {
	if err != nil || cur == 0 {
		return
	}
	base, berr := p.st.TrackProfileBaseline(ctx, consumer, m.name, cur, true, p.baselineTTL)
	if berr != nil {
		return
	}
	// Two conditions, both required. The floor keeps a consumer with a norm of
	// 0.4 from being "anomalous" at 3 requests; the multiple is what makes the
	// judgement relative to the consumer rather than to a global threshold
	// nobody can set correctly for every client at once.
	if cur < int64(p.floor) || base <= 0 || float64(cur) <= base*p.sensitivity {
		return
	}
	// Re-record without learning, so this window does not drag the norm toward
	// the anomaly it just reported.
	_, _ = p.st.TrackProfileBaseline(ctx, consumer, m.name, cur, false, p.baselineTTL)

	detail := fmt.Sprintf("consumer %s %s", consumer, m.why(cur, base))
	p.log.Warn("behaviour profile: consumer departed from its own norm", map[string]any{
		"consumer": consumer, "metric": m.name,
		"current": cur, "baseline": base, "endpoint": endpoint,
		"why": detail,
	})
	p.al.Notify(ctx, alert.SeverityWarning,
		"profile:"+m.name+":"+consumer,
		"Consumer behaviour departed from its own baseline", detail)
}

// record runs every dimension for one completed request.
func (p *profiler) record(ctx context.Context, consumer, endpoint string, status int) {
	n, err := p.st.IncrProfileWindow(ctx, consumer, metricVolume.name, p.window)
	p.observe(ctx, consumer, endpoint, metricVolume, n, err)

	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		n, err := p.st.IncrProfileWindow(ctx, consumer, metricAuthFail.name, p.window)
		p.observe(ctx, consumer, endpoint, metricAuthFail, n, err)
	case http.StatusNotFound:
		n, err := p.st.IncrProfileWindow(ctx, consumer, metricNotFound.name, p.window)
		p.observe(ctx, consumer, endpoint, metricNotFound, n, err)
	}

	d, derr := p.st.TrackProfileDistinct(ctx, consumer, metricEndpoints.name, endpoint, p.window)
	p.observe(ctx, consumer, endpoint, metricEndpoints, d, derr)
}

// BehaviorProfile observes each consumer against its own norm.
//
// Placed after ConsumerID so a caller has a stable identity: with opaque
// credentials and no pseudonym every caller is the same "ip:" consumer and
// "unlike itself" has no meaning. Placed after the proxy in effect — it reads
// the status code, so it acts on the way out.
func BehaviorProfile(cfg config.ProfileConfig, log Logger, st profileStore, al *Alerter) Middleware {
	if !cfg.Enabled {
		return passthrough
	}
	p := &profiler{
		st: st, log: log, al: al,
		window:      cfg.Window,
		baselineTTL: cfg.BaselineTTL,
		sensitivity: cfg.Sensitivity,
		floor:       cfg.MinObservations,
		allow:       map[string]bool{},
	}
	if p.window <= 0 {
		p.window = 5 * time.Minute
	}
	if p.baselineTTL <= 0 {
		p.baselineTTL = 30 * 24 * time.Hour
	}
	if p.sensitivity < 1 {
		// Below 1 every consumer is permanently anomalous against its own norm.
		p.sensitivity = 4
	}
	if p.floor <= 0 {
		p.floor = 20
	}
	for _, c := range cfg.Allowlist {
		p.allow[c] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			// The same header AbuseDetection reads: ConsumerID sets it, and
			// CleanHeaders strips any inbound copy, so it cannot be forged.
			consumer := r.Header.Get("X-Gateway-Consumer-Key")
			if consumer == "" || p.allow[consumer] {
				// An allowlisted consumer is the batch job, the indexer, the
				// monitoring probe — the three things that look anomalous by
				// nature and are the main source of noise in a profile like
				// this. Excluded entirely rather than tuned around.
				return
			}
			p.record(r.Context(), consumer, r.Method+" "+r.URL.Path, rec.status)
		})
	}
}

// profileMetricNames is every dimension this middleware reports on, for the
// admin API and the console. Kept beside the metrics so a new dimension cannot
// be added without appearing here.
func profileMetricNames() []string {
	return []string{
		metricVolume.name, metricAuthFail.name, metricNotFound.name, metricEndpoints.name,
	}
}

// ProfileMetrics is the exported form of the above.
func ProfileMetrics() string { return strings.Join(profileMetricNames(), ", ") }
