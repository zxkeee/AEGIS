# Per-consumer behavioural profiling

**The honest answer to "do you do anomaly detection".**

AEGIS notices when a consumer behaves unlike **itself**. It does this without a
trained model, and that is a decision rather than a shortcut.

## Why not machine learning

A model is the expected answer and the wrong one to build first:

- **It needs labelled traffic that does not exist yet.** A model trained on
  synthetic traffic confirms what was put into it. That is not a detection, it
  is a mirror.
- **It cannot explain a finding.** "Anomaly score 0.87" tells a security team
  nothing they can act on or dismiss, and an unexplainable finding is worse
  than none — it costs attention and returns nothing.
- **This project has measured what unexplained findings are worth.** A
  false-positive assessment produced 101 identical "critical" findings across
  161 requests. What made them worthless was not the count; it was that none of
  them said why.

So each consumer is compared against its own online baseline, and every finding
names the dimension, the observed value and the norm it departed from.

If you need a model — because a questionnaire asks for one, or because your
team has traffic to train on — say so. The baselines here are the input a model
would want anyway, and the honest sequence is: get the traffic, then train on
it, in that order.

## What is measured

Four dimensions, each compared independently. One combined score would hide
which of them moved, which is the only thing an operator needs.

| Dimension | What it catches |
|---|---|
| **volume** | A stolen credential being used by a script |
| **auth_failures** (401/403) | Credential stuffing, privilege probing — a consumer suddenly unable to authorise is either broken or exploring |
| **not_found** (404) | Path enumeration from a consumer that normally knows its endpoints |
| **endpoint_spread** | A fixed integration widening its reach — a deploy, or someone exploring with a valid token |

Each is an EWMA of the consumer's own history, the same machinery the BOLA
baseline has used since A2.

## Configuration

```yaml
security:
  profile:
    enabled: true
    window: 5m            # observation window
    baseline_ttl: 720h    # 30 days: a monthly job is still compared to itself
    sensitivity: 4        # report at 4x the consumer's own norm
    min_observations: 20  # below this a window is noise, not a departure
    allowlist:
      - "jwt:nightly-batch"
      - "jwt:search-indexer"
```

**The allowlist is the main false-positive control.** The batch job, the
indexer and the monitoring probe look anomalous by nature; they are excluded
entirely rather than tuned around. Naming three consumers beats lowering
sensitivity for everyone.

**`min_observations` matters more than it looks.** A consumer whose norm is 0.4
requests per window must not be "anomalous" at three. Below the floor there is
no norm to depart from, only noise to report.

## What it deliberately does not do

- **It never blocks.** A statistical departure is not proof of anything, and
  blocking on one is how a customer's nightly batch gets cut off at 02:00.
  Findings are logged and alerted; enforcement stays with the controls that
  have a deterministic reason to act — WAF, rate limiting, BOLA ownership.
- **It does not learn from an anomalous window.** An attack that persists would
  otherwise become the new normal. The window that produced a finding is
  re-recorded with learning off.
- **It says nothing about a consumer it has not seen enough of.** A new
  integration has no norm, so it is not reported until it has one.
- **It needs a consumer identity.** With opaque credentials and no
  pseudonymisation every caller is the same `ip:` consumer, and "unlike itself"
  has no referent. Enable `consumer_id` first.
- **It fails open and silent.** A Redis outage produces neither a blocked
  request nor an invented finding.

## Where it sits

Innermost of the observers in the chain, because three of its four dimensions
are response status codes: it can only judge a request that has finished.
Inside `ConsumerID`, for the identity reason above.

## What a finding looks like

```
behaviour profile: consumer departed from its own norm
  consumer: jwt:alice
  metric:   auth_failures
  current:  60
  baseline: 2.1
  why:      consumer jwt:alice saw 60 authorisation failures (401/403) against
            a norm of 2.1 — either a broken client or someone probing what a
            valid token reaches
```

The `why` line is the deliverable. An operator reads it and either acts or
dismisses it in one step, without opening a dashboard to find out what the
alert meant.
