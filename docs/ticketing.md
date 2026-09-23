# Filing incidents into Jira or ServiceNow

AEGIS creates one ticket per **incident**, not per event.

That distinction is the whole design. A BOLA campaign is thousands of events and
one incident; an integration that files per event produces thousands of tickets
and is switched off on its first day. The incident register
(`internal/incident`) already does the correlation, so "one ticket per incident"
holds by construction rather than through a deduplication window somebody has
to tune.

## Configuration

```yaml
ticketing:
  enabled: true
  system: jira                       # or servicenow
  base_url: "https://acme.atlassian.net"
  project: "SEC"                     # Jira only
  user: "automation@acme.example"
  min_severity: major                # minor | significant | major
  interval: 1m
  batch: 20
  allow_private: false               # true for a self-hosted tracker
```

The token is an environment variable, never the config file:
**`AEGIS_TICKET_TOKEN`** — a Jira API token, or a ServiceNow password. In
Kubernetes set `secrets.ticketToken`, or supply `ticket-token` through
`secrets.existingSecret`.

With ticketing enabled and no token, the gateway **refuses to start**. Every
call would be rejected at the tracker and only logged here, so the operator
would believe incidents were being filed while the tracker held nothing.

`min_severity` defaults to `major`. A tracker filled with minor findings is a
tracker nobody reads, and the point of this integration is that somebody reads it.

## How it files, and why it polls

A sweep runs every `interval`, asks the register for incidents at or above
`min_severity` that have no ticket, and files them oldest first.

Polling rather than filing at the moment an incident is created is deliberate.
A callback would file sooner, and it would put a network call to a third party
inside the transaction that records the incident — where a slow tracker becomes
a slow gateway and a failed call becomes a lost incident. Polling costs a delay
of at most one interval and makes a tracker outage free: the next sweep picks up
everything it missed, because "has no ticket" is a question about the database
rather than about what happened while the tracker was down.

## Duplicates: what is guaranteed and what is not

The honest description is **at least once, deduplicated on the tracker side**.
Not exactly once — no single database write can promise that across a network.

Three things make a duplicate unlikely and visible rather than pretended away:

1. **A unique local record per incident.** Two gateways racing can both create a
   ticket, and exactly one wins the write. The loser logs the duplicate it made,
   with the reference, instead of discarding the fact — an orphan ticket nobody
   can trace back is worse than a noisy log line.
2. **A search before every create.** Jira gets a label, ServiceNow has a
   `correlation_id` field meant for exactly this. A ticket left behind by a run
   that died before recording its reference is **adopted** rather than
   duplicated.
3. **A deterministic correlation key** (`aegis-<incident id>`), stable across
   restarts and identical on every gateway, because the incident id is itself
   deterministic in the incident's identity and start.

**The gap that remains:** trackers index asynchronously, so a crash in the
window between "the tracker created it" and "a search would find it" can still
produce a second ticket. If the search itself fails, the incident is filed
anyway and the result says the duplicate check did not run — an incident going
unreported because a query failed is the wrong way to fail for something whose
purpose is that somebody finds out.

## Where the reference is stored

In `incident_tickets`, its own table, **not** as a column on `incidents`.

`incidents` is the evidence the signed compliance report is computed from, and
every one of its fields is covered by the integrity ledger's digest. A new
column would mean either a field of the evidence table that nothing commits to,
or a digest change that makes every existing incident read as altered on
upgrade — a routine deployment looking exactly like tampering, on the one
mechanism whose value is that its answer means something.

A pointer to a Jira issue is also not evidence about what happened. It is
bookkeeping about another system, and it belongs beside the register.

## What the ticket says, and what it does not

The description carries the incident id, class, subject, severity, first-seen
time and correlated event count — enough to find it in the console.

It states plainly that AEGIS's severity is **its own classification of observed
activity and not a regulatory one**. NIS2 Art. 23 and DORA Art. 18 thresholds
are decided by an operator in the incident register; a ticket does not make that
decision and must not be read as having made it.

## Self-hosted trackers

`allow_private: true` lets a sink reach Jira Data Center or a ServiceNow
instance on the operator's own network. Loopback, link-local
(`169.254.169.254`, cloud metadata) and multicast stay refused regardless, and
the decision is made on the resolved address — a public hostname with a private
A record is judged by where the connection actually goes.
