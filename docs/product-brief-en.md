# AEGIS — API Security Gateway

**Self-hosted API security. Discovery, runtime protection and regulator-grade
evidence — in one binary, with no traffic leaving your infrastructure.**

> This is the outward-facing brief: for a partner, an investor, a grant
> assessor or a first customer conversation. Positioning is inherited from
> [`PRODUCT.md`](./PRODUCT.md); implementation status from
> [`../ROADMAP.md`](../ROADMAP.md). Where this document and the code disagree,
> the code wins and this document is wrong — `make doc-drift` enforces that in
> CI.

---

## The three pillars

The category has settled on three questions, in this order. A buyer evaluating
Akamai, Salt or Noname will ask them in exactly this sequence, so this is how
AEGIS answers them.

### Pillar 1 — See: what APIs do you actually have?

You cannot protect what you cannot see, and nobody's documentation matches
their traffic.

AEGIS builds the inventory **passively, from real traffic**: every endpoint,
method and host, with paths normalised (`/users/42` → `/users/{id}`) so a
catalog stays readable instead of exploding into a million rows.

On top of the inventory:

- **Data classification.** Credit cards (Luhn-validated), national IDs, emails,
  phone numbers — typed detectors, not a regex sweep, so "PCI data on this
  endpoint" means something. Types persist per endpoint.
- **Posture.** Every endpoint is classified protected / partial / unprotected /
  shadow and scored 0–100. A shadow endpoint returning PII to anonymous callers
  is the finding that starts most conversations.
- **Consumer graph.** Who calls what, how often, with which credentials. This
  is the foundation the detection in Pillar 2 is built on, and most
  firewall-derived competitors do not have it.
- **Spec drift.** Import your OpenAPI and see documented-versus-actual, both
  directions: undocumented endpoints in production, documented endpoints nobody
  calls.

### Pillar 2 — Protect: stop what a signature firewall cannot see

A signature WAF knows "this looks like SQL injection". It does not know that
*this consumer normally touches three objects and has just walked three
hundred*. That is the class of attack the industry calls BOLA, it is #1 in the
OWASP API Top 10, and it is what AEGIS was built for.

- **BOLA / object-level authorisation.** Two detections, not one. Enumeration
  (a consumer sweeping object IDs) and **single-object IDOR** — a consumer
  successfully reading one object belonging to someone else. Ownership is
  confirmed from the response body, not guessed, so a confirmed finding is a
  confirmed finding. Cross-owner access can be blocked **before** the request
  reaches your backend.
- **BFLA / function-level authorisation**, on verified JWT roles.
- **Behavioural profiling.** Each consumer measured against its own baseline on
  four named dimensions: volume, authorisation failures, missing paths,
  endpoint spread. Every finding says which dimension and by how much — a
  number an operator can act on or dismiss in one read.
- **OWASP CRS v4** through Coraza, with anomaly scoring and a monitor mode for
  tuning before enforcement.
- **Data-leak prevention** on responses, streaming-safe, with WebSocket and
  server-sent events passing through intact.
- **Schema enforcement.** Requests validated against your OpenAPI contract:
  undocumented fields refused, which closes mass assignment.

### Pillar 3 — Prove: evidence a regulator and an auditor accept

This is where AEGIS diverges from the category, and it is deliberate.

- **Mapping to NIS2 (Art. 21), DORA (Art. 8–10, 17–19) and ISO 27001:2022**,
  via the OWASP API Top 10.
- **Signed reports.** Ed25519, on a key separate from every other secret, with
  a standalone verifier (`reportverify`) that refuses to run against a key
  taken from the document it is checking.
- **An incident register** with NIS2 Art. 23 deadlines and DORA Art. 18
  classification, separating what the gateway observed from what an operator
  asserted. Closing an incident does not erase a missed deadline.
- **Tamper-evident records.** The forensic log is sealed hourly with Merkle
  roots in a signed chain; the incident register keeps an append-only ledger
  with a signed head; the admin action trail is chained and signed too. Deleting
  a row, editing one, or removing a tail is detectable — including when the
  operator does it.
- **Every signed document states what it does not establish.** The system
  refuses to sign a document that carries no limits section.

That last line is the product's character in one sentence. **The signing key is
held by the party being audited**, so a signature proves the document was not
altered after it was produced — not that it was assembled from complete data.
AEGIS says so, inside the signed document, rather than letting a reader assume
otherwise. The correct word is tamper-**evident**, never tamper-proof.

---

## Why self-hosted is the moat

Every capability above exists somewhere in the market, usually more mature. The
part that cannot be copied by an incumbent is **where it runs**.

Salt, Noname, Imperva and Akamai's API security are SaaS. They need a copy of
your traffic in their cloud. For a DORA-regulated fintech, a hospital, a
public-sector body, or a Ukrainian product company selling into the EU, that is
sometimes not a preference — it is a legal bar they cannot clear.

AEGIS is **one Go binary**. No agents, no sidecars, no SaaS tenancy, no traffic
leaving the customer's network. Data residency is the default rather than an
enterprise add-on.

It also deploys two ways in one process, which competitors usually make you
choose between:

- **Mirror mode** — the customer's nginx sends a copy of requests; AEGIS never
  sits in the request path. You can stop the gateway in the middle of a pilot
  and nothing changes for their traffic. This removes the objection that ends
  most first conversations.
- **Inline** — full enforcement, with an observe mode that inspects and records
  while blocking nothing, for the transition.

---

## What it costs to run

Measured on loopback, three runs per mode, published with method and caveats in
[`tests/load/overhead-results-2026-09-23.md`](../tests/load/overhead-results-2026-09-23.md):

| Mode | Added latency (p50) |
|---|---|
| Observe (what a pilot runs) | **+1.1 … 1.6 ms** |
| Full enforcement — WAF blocking, DLP, discovery, BOLA, bot, IP guard, behaviour | **+1.8 … 2.7 ms** |

Stated as a range rather than a number because two identical runs differed by
0.9 ms. This is the gateway's own cost isolated on one machine; it is not a
capacity benchmark and not what a remote client experiences.

---

## Integrations

Alerts and evidence go where the security team already works: **Splunk HEC**
and **Elasticsearch** (ECS field names, so events land in existing dashboards),
Slack or a generic webhook, **Jira and ServiceNow** for ticketing — one ticket
per *incident*, not per event, deduplicated on the tracker side. Prometheus
metrics on the admin plane. Helm chart and Compose stack for deployment.

---

## Where the product actually stands

Stated plainly, because a grant assessor and a serious investor will both find
out anyway, and finding out from us is worth more than finding out later.

**Engineering maturity is high.** 27 300 lines of Go with 27 800 lines of tests
— more test code than product code. Per-package coverage floors from 70% to 100%
enforced in CI. Eleven security invariants encoded as scripts, each one a bug
that shipped once and cannot ship again. Mutation testing as
a working discipline, not a slogan: the code is deliberately broken to prove the
tests notice, and that practice has found eleven tests that were passing for
the wrong reason — each one listed individually, which is why the number is
eleven and not a rounder one.

**The release gate stands at 52 items closed, 17 partial, 3 open**, and two of
the three open items are not tasks — they are honestly recorded limits of what
any single-database system can prove.

**Commercially it is at zero.** No pilot, no paying customer, no independent
penetration test. That is the gap, it is known, and it is what a Polish entity
and a first customer conversation are for.

**Technology readiness: TRL 5, arguably 6.** The whole system runs and is
verified end to end in our own environment. TRL 7 needs one deployment on
somebody else's real traffic — a single pilot, not a year of work.

---

## What is deliberately not built

- **No trained ML model.** A model needs labelled traffic that does not exist
  before a deployment does, and it cannot explain a finding. Per-consumer
  baselines ship instead, and they are the input a model would want anyway.
- **No external anchor for the signed evidence.** Everything lives in the
  customer's own database, so an operator holding the signing key could rewrite
  a record and re-sign it. A timestamp authority or transparency log closes
  this; it is not built, and no document here claims otherwise.
- **No PCI-DSS, HIPAA or GDPR report templates** — NIS2, DORA and ISO 27001
  only.
- **No SAML, SCIM or MFA of our own.** OIDC covers this through the customer's
  identity provider.
- **No eBPF sensor.** Mirror mode covers "I will not put you in my request
  path" in two days rather than two months.
