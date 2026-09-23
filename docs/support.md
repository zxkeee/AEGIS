# Support and service levels

This is the document a buyer asks for on the first technical call, and the
honest version is short.

## What this is today

AEGIS is maintained by **one engineer**. There is no on-call rotation, no
24/7 desk, and no legal entity to counter-sign a service-level agreement.
Everything below is a commitment that can actually be kept at that size.

An enterprise SLA with a one-hour response target would be easy to write and
impossible to honour, and a customer discovers which it was during their first
incident — the worst possible moment to find out. What follows is deliberately
modest and deliberately real.

If you need contractual response times backed by a company, say so early. That
is a reasonable requirement and this project does not meet it yet; the shape it
would take is in **A paid SLA, when there is one** below.

## Severity

Severity is about **impact on the customer's traffic**, not about how
interesting the bug is.

| | Definition | Example |
|---|---|---|
| **S1 — traffic affected** | The gateway is down, refusing legitimate traffic, or corrupting responses | Fail-closed triggered by a Redis outage and blocking everything; a WAF rule rejecting a valid API |
| **S2 — protection degraded** | Traffic flows, a security control does not | A detection stopped firing; alerts stopped reaching the SIEM; the forensic log stopped being written |
| **S3 — evidence or reporting affected** | Traffic and protection are fine, the record is not | A signed report will not generate; a seal verification reports a false mismatch |
| **S4 — everything else** | Questions, documentation, feature requests | "How do I scope a rule to one route?" |

**Mirror mode has no S1.** A mirror carries a copy of the request and no
response, so the customer's traffic does not pass through AEGIS and cannot be
affected by it. That is the point of starting there, and it is why a pilot in
mirror mode needs far less from this page than an inline deployment does.

## Response targets

Targets, not guarantees. They describe intent and past behaviour, and nothing
here is contractual.

| Severity | First response | Working on it |
|---|---|---|
| S1 | Same working day | Until it is resolved or worked around |
| S2 | 1–2 working days | Next release |
| S3 | A few working days | Next release |
| S4 | Best effort | When it makes sense |

Working days are Monday to Friday, European hours. A message sent on Friday
evening is read on Monday. Saying otherwise would be pretending there is a
second person.

**Workaround first, fix second.** For an S1 the first goal is to get traffic
healthy — which usually means `observe: true`, disabling one control, or
removing the gateway from the path entirely — and only then to find the cause.
Every control in AEGIS can be switched off through config and hot-reload, with
no restart and no redeploy. That is a support property as much as an
operational one.

## How to report

There is no ticket portal. Use whatever channel was agreed for the pilot, and
include:

1. **What broke, and what you expected instead.**
2. **When it started**, with a timezone.
3. **The gateway version** — `gateway -version`.
4. **A diagnostic bundle** — `make support-bundle` (see below).
5. **A request id** if you have one. Every response carries `X-Request-ID`, and
   it is the fastest way to find one request in the forensic log.

### Diagnostic bundle

```bash
make support-bundle          # writes support-bundle-<timestamp>.tar.gz
```

It collects the gateway version, the effective configuration **with every
secret redacted**, the names (never the values) of the `AEGIS_*` variables that
are set, the last 500 log lines, and — when `-a` names the admin endpoint —
health and readiness. It never includes request bodies, forensic log contents,
database rows, or the contents of any secret.

Read it before sending it. It is your data and it leaves your infrastructure.

The redaction is not taken on trust: `scripts/check-support-bundle.sh` plants a
canary value in every secret-bearing field of a configuration, runs the bundle,
and fails if any canary survives. It runs in CI and in `make preflight`. That
check found a real omission on its first run — `consumer_id.salt` was not in the
list of secret-looking key names, and it is the value that makes the consumer
catalog irreversible.

## Security vulnerabilities

Not here — see [`SECURITY.md`](../SECURITY.md). Report privately through a
GitHub Security Advisory, never a public issue and never this channel.

## What is covered

- The gateway, the admin API and the console, as shipped.
- The Helm chart and the Compose stack.
- The verification tools (`reportverify`) and the reference SDK
  (`sdk/gatewayverify`).
- Configuration help: what a control does, how to scope it, why something is
  or is not being detected.

## What is not

- **Your infrastructure.** Redis, PostgreSQL, Kubernetes, your load balancer
  and your TLS termination are yours. Failure modes caused by them are
  diagnosed as far as possible and fixed by you.
- **Writing your WAF exclusions.** Tuning false positives against a specific
  application is consulting work, not support. Guidance is free; doing it is
  not.
- **Regulatory advice.** AEGIS maps findings onto NIS2, DORA and ISO 27001
  controls and states what it does not evidence. Whether your organisation
  meets an obligation is a question for your counsel, and any answer from here
  would be worth exactly what you paid for it.
- **Data recovery.** Seals make tampering detectable, not reversible. A deleted
  forensic row is gone; a Merkle root is not a backup. Back up PostgreSQL.

## Upgrades and versions

- Only the **latest release** receives fixes. There are no maintenance branches
  and there is no back-porting, because one engineer maintaining two lines
  produces two half-maintained lines.
- Security fixes ship as a patch release with the issue named in the
  `CHANGELOG`.
- Breaking changes are called out in the `CHANGELOG` with the migration path.
  The signed-document formats are versioned (`aegis-attest-v1`,
  `aegis-forensic-seal-v1`) so an old artifact stays verifiable after an
  upgrade.

## Maintenance windows

None are required. Configuration is hot-reloaded and the gateway drains
in-flight requests on shutdown, so a rolling update needs no window. A
PostgreSQL migration runs on startup and is idempotent.

## A paid SLA, when there is one

For a customer who needs contractual terms, this is the shape it would take —
written here so the conversation starts from something concrete rather than
from nothing:

| | |
|---|---|
| **Coverage** | Business hours in one named timezone, or 24/7 for S1 only |
| **S1 response** | Contractual, with a credit if missed |
| **Named contact** | A person, not an address |
| **Quarterly review** | Detections fired, false positives tuned, what changed |
| **Prerequisites** | A legal entity on this side, a DPA, and enough revenue to justify being woken up |

The last row is the honest blocker, and it is not one a customer can be asked
to overlook. It is also the one that disappears the moment there is a first
paying customer.
