# Observe / Pilot mode

`observe: true` puts AEGIS into a **guaranteed non-disruptive** posture for a
first pilot on a partner's live traffic. Every control still inspects and
records — but nothing is blocked, no response body is modified, and no control
fails closed. It is the deployment that lets you produce a findings report with
**zero risk to the partner's production**.

```yaml
observe: true            # top-level; overrides the security controls below
security:
  waf:   { enabled: true }        # detects attacks (DetectionOnly), never blocks
  dlp:   { enabled: true }        # classifies PII, never redacts the body
  auth:  { enabled: true, secret: ... }   # extracts identity, never returns 401
  abuse: { enabled: true, object_ownership: true }  # flags BOLA/BFLA, never blocks
```

## What observe mode guarantees

Coercion is applied by `GatewayConfig.ApplyObserveMode()` after config validation,
on **startup and every hot-reload**, so it cannot be bypassed by a per-route
override or a later edit:

| Control | Enforce mode | Observe mode |
|---------|--------------|--------------|
| WAF | blocks (403) | **DetectionOnly** — matches + logs, forwards the request |
| DLP | redacts PII in the response | **classifies + flags the endpoint, body passes through unmodified** |
| JWT auth | 401 on missing/invalid token | **extracts identity from a valid token, otherwise passes through** |
| Abuse (BOLA/BFLA) | can block / proactively deny | **detect-only** |
| Schema | rejects (422) | monitor |
| Rate limit, IP guard, threat feed, bot, challenge, behavior | block / throttle / ban | **disabled** (no discovery value, only risk) |
| `fail_closed` (rate-limit, IP-guard, JWT revocation) | may deny on Redis outage | **forced off — never fail closed** |
| per-route `rate_limit` override | throttles | **cleared** |

What still runs and produces the pilot's value: **passive discovery** (catalog,
posture, shadow-API detection), **DLP classification** (which endpoints leak
which PII classes), **BOLA/BFLA detection** (identity-attributed when a valid
token is present), **WAF detection**, and **schema drift**.

A loud `OBSERVE MODE ACTIVE` warning is logged at startup and on every reload.

## Why "observe" and not the customer's own auth off?

JWT auth in observe mode is *soft*: a valid token is still parsed, its identity
propagated and signed, so BOLA/BFLA attribution and consumer analytics work — but
a missing, expired, malformed or revoked token is passed **through** rather than
rejected. AEGIS must never block traffic the customer's own backend would have
accepted; the backend remains the source of truth for enforcement during a pilot.

## Deploying a pilot

1. Copy `config/gateway.pilot.yaml` and fill in its two `TODO`s: the partner's
   real backend(s) under `routes`, and `trusted_proxies` if there's an LB/CDN in
   front of AEGIS. It already ships with `observe: true` and every detection
   control enabled — nothing to hand-tune before going live.
2. Run it via `docker-compose.yml` (`command: ["--config", "config/gateway.pilot.yaml"]`)
   with `AEGIS_ADMIN_SECRET`, `AEGIS_REDIS_PASSWORD` set — the bundled Redis and
   PostgreSQL cover the catalog/findings/consumer graph out of the box.
3. Let it run for a week.
4. Read the findings from **two views** — they cover different things:
   - `GET /api/findings` — catalog-derived findings (PII exposed without auth,
     shadow endpoints), critical-first; add `?format=csv` for a downloadable
     report you can hand to the partner without console access.
   - `GET /api/compliance` and `GET /api/block-log` — **runtime BOLA/BFLA
     events** (confirmed single-object IDOR, enumeration, privileged-path
     access), mapped to NIS2/ISO 27001/OWASP in `/api/compliance`. This is the
     flagship detection and does **not** appear in `/api/findings`.

   Also: `GET /api/catalog` (also `?format=csv`) and `GET /api/posture/summary`.

   Confirmed single-object IDOR detection requires `security.abuse.owner_fields`
   to name the response-body field that carries the object's owner id —
   `config/gateway.pilot.yaml` ships with this empty by design (it's
   app-specific); leaving it unset means only the coarser enumeration signal
   runs, not the confirmed-from-body detection that's this product's main
   differentiator.

   If the API does not use JWTs at all, set `security.consumer_id.enabled: true`
   as well (it is on in the template). Object-ownership detection needs to tell
   one caller from another, and without it every caller holding an opaque token,
   API key or session cookie is recorded as the same `ip:<addr>` consumer — one
   consumer for the whole estate, which makes "did this caller read someone
   else's object" a question with no answer. Note the limit: a pseudonym is a
   hash of a credential, so it can never be compared against an owner id in a
   response body. Such callers get enumeration and first-accessor detection, not
   the confirmed-from-body IDOR finding.

   **Open a real response before setting it.** A flat `user_id` is the easy
   case, but most APIs return the owner as an object, and then you need the
   dotted path to the id inside it:

   ```yaml
   owner_fields: ["user.id", "owner.id"]        # {"user": {"id": 70422, …}}
   owner_fields: ["data.attributes.owner_id"]   # JSON:API style
   ```

   Forgejo, GitHub, GitLab and Stripe all nest it. Getting this wrong fails
   silently — the lookup finds nothing, the detection never fires, and no error
   appears anywhere, so the pilot looks quiet when it is in fact blind.

> Note: observe mode is still **inline** — AEGIS sits in the request path, so it
> adds a proxy hop even though it blocks nothing. Measured overhead is not
> distinguishable from enforce mode's own cost at 20 VUs — see
> `tests/load/observe-mode-results-2026-07-31.md`. True out-of-band ingestion
> (traffic mirroring / eBPF, ROADMAP B1) removes the path entirely and is the
> next step for partners who cannot add any inline hop.
