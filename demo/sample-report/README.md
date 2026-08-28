# Sample findings report — generator

Produces `docs/assets/AEGIS-Sample-Findings-Report.{html,pdf}`: the artifact a
prospect sees before they agree to a pilot.

The point of this directory is that **the report is not written by hand**. A real
gateway runs in front of a deliberately flawed fictional API, ordinary traffic is
driven through it, and every figure in the document is exported from what the
gateway actually observed. If the product stops detecting something, the report
stops claiming it — which is the only way an artifact like this stays honest as
the code moves.

## Run it

```bash
./demo/sample-report/generate.sh      # stand up, drive ~2,700 requests, export to out/
python3 demo/sample-report/render.py  # out/ -> docs/assets/…Report.html
```

Then render the PDF with the same headless-Chrome step used for the other
documents in `docs/assets/`.

Requires `go`, `curl`, `redis-server`, and a reachable PostgreSQL (the catalog
and findings live there — without it there is nothing to export). Override the
database with `POSTGRES_DSN`; everything else is built to a temp dir and torn
down on exit.

## What the scenario contains

`backend/main.go` is "Northwind Payments", fictional and deliberately flawed. It
is estate-shaped on purpose — a v1 that grew, a half-done v2 migration, a partner
API, an admin surface, an "internal" namespace — because a five-endpoint toy
produces a report a CISO reads as a lab demo rather than a picture of their own
systems. The run discovers ~28 endpoints from ~2,700 requests by 11 consumers.

| Planted flaw | What AEGIS reports |
|---|---|
| `/api/v1/customers/{id}`, `/…/cards`, `/internal/reports/export` return PII behind routes that require nothing | `sensitive_data_no_auth`, critical, OWASP API3 |
| `/api/v1/orders/{id}` hands any order to any authenticated caller | `bola_object_ownership`, confirmed from the response body, OWASP API1 |
| One batch job walks order ids | `bola_enumeration` against the absolute ceiling |
| `/api/v1/admin/*` reachable by a consumer holding only `user` | `bfla_privileged_access`, OWASP API5 |
| `openapi.yaml` is behind production | 19 × `undocumented_endpoint` / `undocumented_method`, OWASP API9 |

Ordinary traffic reads its *own* objects (see `ownOrder` in `traffic/main.go`).
That matters: if everybody reads everybody's records, "confirmed IDOR" stops
distinguishing anything and the finding is noise. With it, the 139 confirmed
detections concentrate on the one job that genuinely misbehaves.

`gateway.yaml` gives each route a different control mix on purpose (protected /
partial / unprotected), because a uniform estate is not what a posture report is
for.

All data is synthetic: RFC 2606 `example.com` addresses and the standard test
card numbers. No real person or company appears anywhere.

## Deliberate configuration choices

`abuse.adaptive` is **off**. Adaptive baselines compare a consumer against its
own learned norm, and a 30-second scripted run establishes no norm worth
comparing against — with it on, ordinary browsing (a user opening a dozen
invoices) trips as "4× baseline" and lands in the report as a critical false
positive. On a real week-long pilot the baseline is real and adaptive is the
better setting; for a sample the absolute ceiling is the honest one.

The export pulls `GET /api/block-log?limit=1000` rather than the default 100.
The ring buffer holds a thousand events and a single order sweep produces enough
detections to fill the first hundred on its own — at the default, every BFLA
detection fell out of the exported window and the report quietly under-counted.

## Two failure modes the script guards against

Both of these produced a confidently empty report the first time and are now
hard errors rather than silent successes:

1. **Traffic not reaching the backend.** A route declared as `/api/v1/customers`
   matches only that exact path in `net/http`'s `ServeMux` — it does *not* cover
   `/api/v1/customers/7`. Prefix routes need the trailing slash. Step `3b`
   probes representative paths and aborts if any is not `200`; the gateway also
   now warns about such routes at startup (`exactMatchRoutes` in
   `internal/gateway/chain.go`), since this cost real debugging time twice.
2. **Export silently rate-limited.** The admin plane throttles itself (5 req/s,
   brute-force protection), so a tight export loop gets `Access Denied` written
   into the artifact instead of JSON. `fetch()` paces, retries and validates each
   response.

## Regenerating after a product change

Re-run both commands. If the numbers in the report move, that is the product
telling you something changed — reconcile it before shipping the new PDF, don't
paper over it.
