# Sending alerts to a SIEM

AEGIS delivers security alerts to Splunk (HTTP Event Collector) and to
Elasticsearch, in addition to whatever webhook is configured for on-call.

## What a SIEM receives, and what it does not

It receives **alerts** — the events a control decided were worth raising:
confirmed BOLA, a BFLA attempt on a privileged path, an IP blocked, a
behavioural threshold tripped.

It does **not** receive every request the gateway saw. That is the forensic log,
which stays in PostgreSQL and is read through `/api/block-log` or queried
directly. The distinction matters commercially as well as technically: a SIEM
is priced on ingest volume, and the two differ by orders of magnitude.

## Configuration

```yaml
alerting:
  webhook_url: "https://hooks.slack.com/services/..."   # optional, unchanged
  min_severity: critical                                 # what pages on-call

  sinks:
    - type: splunk_hec
      url: "https://splunk.internal:8088/services/collector/event"
      index: aegis
      min_severity: info        # a SIEM usually wants everything
      allow_private: true       # Splunk is on the internal network

    - type: elastic
      url: "https://es.internal:9200/aegis-alerts/_doc"
      min_severity: warning
      allow_private: true
```

Each sink has its own threshold. The common shape is exactly the one above: the
SIEM takes everything, on-call is paged only for criticals. A single shared
threshold would be wrong for one of the two in every deployment.

## Credentials

Never in the config file, like every other secret here:

| Variable | Used by |
|---|---|
| `AEGIS_SPLUNK_HEC_TOKEN` | `splunk_hec` sinks |
| `AEGIS_ELASTIC_API_KEY` | `elastic` sinks (omit for a cluster with security disabled) |

In Kubernetes, set `secrets.splunkHecToken` / `secrets.elasticApiKey`, or supply
them through `secrets.existingSecret` under the keys `splunk-hec-token` and
`elastic-api-key`.

A Splunk sink with no token is **refused at startup**. The collector rejects
every event sent without one and rejects it at the far end, so the gateway would
log successful deliveries while the SIEM held nothing — believing you have an
audit trail you do not have is worse than knowing you have none.

## `allow_private` and why it is not the default

The gateway refuses to connect to internal addresses. That rule is right for a
webhook, where a private address means something has gone wrong, and wrong for a
SIEM, which lives on `10.0.0.0/8` in essentially every deployment that has one.

`allow_private: true` relaxes it for that sink and only that sink. What stays
refused regardless:

- **loopback** — a collector on `127.0.0.1` would be the gateway posting alerts
  to its own admin API;
- **link-local** — `169.254.169.254` is cloud metadata, the highest-value SSRF
  target there is, and `metadata.google.internal` resolves to it;
- **unspecified and multicast** — not destinations.

The decision is made on the *resolved* address, so a public hostname with a
private A record is judged by where the connection actually goes rather than by
how it is spelled.

## Wire formats

**Splunk HEC** — the standard envelope, `sourcetype: aegis:alert`. `time` is a
numeric epoch, which is what HEC requires; a string there is rejected at the
collector and the batch is dropped with nothing on this side to show for it.

**Elasticsearch** — Elastic Common Schema field names (`@timestamp`,
`event.kind`, `event.dataset`, `log.level`, `message`), so the events land in
dashboards that already exist instead of needing a bespoke mapping.

## Failure behaviour

Delivery runs off the request path, on a detached goroutine with its own
deadline, so nothing here can slow a request or fail one.

Sinks are delivered to **concurrently**. One collector that has stopped
answering would otherwise consume the whole deadline and the sinks after it
would never be attempted — an outage in a system nobody is watching would
silently disable the one somebody is.

A failed delivery is logged as an error and dropped. **There is no queue and no
retry:** an alert that could not be delivered is gone. What this buys is that a
SIEM outage can never grow memory in the gateway or delay traffic; what it costs
is that the SIEM's record has a gap exactly when it was unreachable. The
forensic log in PostgreSQL does not have that gap, and is the record to reach
for when the question is "what happened during the outage".
