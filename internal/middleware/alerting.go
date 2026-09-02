package middleware

import (
	"context"
	"time"

	"api-gateway/internal/tenant"
)

// alertDedupWindow is how long one alert key stays quiet after firing.
//
// The trigger for every alert here is attacker-controlled: a caller decides how
// often it enumerates objects or trips the behaviour score. Without a gate, one
// loop turns into thousands of webhook POSTs — which floods the operator's
// on-call channel, gets the gateway rate-limited by Slack or PagerDuty, and
// buries the first alert (the only one that mattered) under the rest. Five
// minutes is long enough that a sustained attack costs one message per phase,
// short enough that a genuinely new incident is not swallowed.
const alertDedupWindow = 5 * time.Minute

// alertDeliveryTimeout bounds one delivery attempt, so a webhook that accepts a
// connection and never answers cannot hold a goroutine indefinitely. The
// engine's HTTP client has its own timeout; this also covers the wait to start.
const alertDeliveryTimeout = 15 * time.Second

// Alerter is the out-of-band notification path for security events: it delivers
// to the configured webhook and mirrors to the log, without the request that
// triggered it waiting for either.
//
// It exists because the alert engine had no callers at all. It was constructed
// at startup, threaded into the admin server, configured (alerting.webhook_url,
// format, min_severity), validated, and documented in the README as something
// that "already delivers webhook alerts" — while Fire was invoked from nothing
// but its own test. An operator could point it at PagerDuty, see no error, and
// believe they would be paged on a BOLA detection. Silence was indistinguishable
// from no attacks.
//
// Three properties are enforced here rather than at each call site, because a
// call site that forgets one is worse than no alert at all:
//
//   - Delivery is asynchronous and on a DETACHED context. Firing inline would
//     add the webhook's timeout to the request. Worse, carrying the request's
//     context means an attacker cancels the alert about their own attack simply
//     by aborting the connection — the POST would be cancelled before it left.
//     The tenant is carried across so the alert is still scoped correctly.
//   - Deliveries are deduplicated per key and tenant (see alertDedupWindow).
//   - Nothing here blocks, rewrites or rejects a request, so this path stays
//     live in observe mode, where recording IS the product.
type Alerter struct {
	engine AlertEngine
	rate   RateLimiter
	log    Logger
}

// NewAlerter wires the notification path. A nil engine disables delivery; the
// returned *Alerter is still safe to call.
func NewAlerter(engine AlertEngine, rate RateLimiter, log Logger) *Alerter {
	return &Alerter{engine: engine, rate: rate, log: log}
}

// Notify delivers a security alert, at most once per dedupKey per tenant per
// alertDedupWindow. It returns immediately; delivery happens on its own
// goroutine. dedupKey identifies the alert, not the request — include the event
// type and the subject it is about (a consumer, an IP), never a value that
// varies per request, or deduplication has nothing to collapse.
func (a *Alerter) Notify(ctx context.Context, level, dedupKey, title, body string) {
	if a == nil || a.engine == nil {
		return
	}

	// Detach from the request before doing anything, so neither the dedup check
	// nor the delivery can be cancelled by the caller hanging up.
	bg, cancel := context.WithTimeout(
		tenant.With(context.Background(), tenant.From(ctx)), alertDeliveryTimeout)

	go func() {
		defer cancel()
		if a.rate != nil {
			n, err := a.rate.IncrRate(bg, "alert:"+dedupKey, alertDedupWindow)
			// On a store outage the count is unknown. Deliver rather than drop:
			// a duplicate page is a nuisance, a missed one is the failure this
			// whole path exists to prevent.
			if err == nil && n > 1 {
				return
			}
		}
		a.engine.Fire(bg, level, title, body)
	}()
}
