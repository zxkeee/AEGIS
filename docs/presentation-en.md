# AEGIS — Presentation Content (English)

> Plain content draft, no visual design yet — visual style will be applied
> once a design reference is provided. Structure: problem, why us, how it
> works, architecture, how it's deployed.

## The problem we solve

Modern companies expose a large and constantly changing surface of APIs.
This is hard to secure for structural reasons:

- **Forgotten APIs.** Endpoints ship faster than they're documented.
  Forgotten and deprecated-but-still-reachable endpoints are a leading cause
  of breaches, because nobody is watching them.
- **Inconsistent protection.** Each team configures auth and rate limits its
  own way. There's no single picture of what's actually protected.
- **No visibility into who calls what.** Answering "who calls this endpoint,
  and how much?" usually isn't quick — the data is scattered across dozens
  of service logs.
- **Data leaking in responses.** Personal and payment data leaks out of API
  responses silently — until someone reports it from the outside.

## Why us

Normally these are three separate products from three separate vendors: an
**API Gateway** (proxy, load balancing), a **WAAP** layer (firewall, rate
limiting, bot mitigation, data-leak protection, identity verification), and
an **ASPM** platform (API catalog, risk scoring, analytics). AEGIS is all
three in one product — one deployment instead of three integrations.

The real differentiator isn't "we also have a firewall" — everyone has a
signature firewall. AEGIS builds an **API catalog and a "who calls what"
graph** from day one — and object-level data-leak detection (section below)
is built directly on top of that graph. Most "just a firewall" competitors
don't have this foundation at all.

AEGIS is also **self-hosted, no mandatory cloud dependency**: the only
external dependencies are Redis and PostgreSQL — infrastructure most
companies already run. Nothing phones home to an external service.

## How it works

AEGIS sits in front of your APIs like a checkpoint: it lets legitimate
traffic through, turns away the malicious kind, and records what it sees
along the way.

A request passes through four checks, in this order:

1. **Rate and reputation** — is this an automated attacker? (IP reputation,
   rate limits, bot detection.)
2. **What's inside the request?** — signature-based inspection (WAF) for
   known attack patterns.
3. **Who is this, and what are they allowed to do?** — identity
   verification and authorization checks.
4. **Does the response leak anything, and does behavior look normal over
   time?** — data-leak protection and behavioral analysis.

A request rejected at steps 1–2 is dropped before it's ever recorded in the
API catalog — so attack noise doesn't pollute the map of your real API. A
request that clears steps 1–2 is recorded in the catalog regardless of what
happens to it afterward — including a later rejection at steps 3–4.

## What the system is made of

- **Two ports, one process.** One port for real client traffic, a separate
  port for management/dashboard — kept apart so an attack on the first
  doesn't cut off access to the second.
- **Redis** — everything fast and short-lived: rate-limit counters, IP
  blocklists, behavioral scores, sessions.
- **PostgreSQL (optional)** — the API catalog and the forensic log. Without
  it, AEGIS still works normally; it just doesn't keep a long-term catalog.
- **Config reloads live.** A rule change takes effect without a restart and
  without dropping active connections.
- **Multi-tenancy.** When several clients share one deployment, their data
  is isolated, with an extra safeguard enforced at the database level
  itself.

## How it's deployed

**Packaging:** a single Docker image. Then a choice of how to run it:

- **Docker Compose** — one server, for a demo or a first pilot. Simple, fast
  to validate on real traffic without a large upfront investment.
- **Kubernetes + Helm** — multiple replicas behind a load balancer,
  autoscaling — the standard shape for production infrastructure.

**Rollout happens in stages**, so a pilot can never break a client's
production traffic:

1. **Observe** — only watches and records, blocks nothing. Builds the API
   catalog, shows what would have been rejected.
2. **Tuning** — false positives are removed based on the collected data.
3. **Enforcement** — real blocking and rate limits are switched on.
4. **Expansion** — the same pattern is rolled out to the rest of the
   client's services.
5. **Steady state** — ongoing work against the posture report: closing
   whatever is still unprotected.

## Where things stand

The product is engineered and tested — controls have been verified,
including behavior under live infrastructure outages. What's still open: an
independent third-party audit, and the first pilot on real production
traffic — both currently in progress.
