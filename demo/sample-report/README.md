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
./demo/sample-report/generate.sh      # stand up, drive traffic, export to out/
python3 demo/sample-report/render.py  # out/ -> docs/assets/…Report.html
```

Then render the PDF with the same headless-Chrome step used for the other
documents in `docs/assets/`.

Requires `go`, `curl`, `redis-server`, and a reachable PostgreSQL (the catalog
and findings live there — without it there is nothing to export). Override the
database with `POSTGRES_DSN`; everything else is built to a temp dir and torn
down on exit.

## What the scenario contains

`backend/main.go` is "Northwind Payments", fictional and deliberately flawed.
The weaknesses are the ones that actually show up in real estates:

| Endpoint | The flaw |
|---|---|
| `GET /api/v1/customers/{id}` | Returns PII (email, phone, PAN); the route in front of it requires nothing. The "internal-only" endpoint that was never locked down. |
| `GET /api/v1/orders/{id}` | Requires auth, but hands any order to any authenticated caller — a textbook IDOR. The true owner is in the body as `user_id`. |
| `GET /internal/reports/export` | Bulk customer dump, unauthenticated, because "it's on an internal path". |

`gateway.yaml` gives each route a different control mix on purpose (protected /
partial / unprotected), because a uniform estate is not what a posture report is
for.

All data is synthetic: RFC 2606 `example.com` addresses and the standard test
card numbers. No real person or company appears anywhere.

## Two failure modes the script guards against

Both of these produced a confidently empty report the first time and are now
hard errors rather than silent successes:

1. **Traffic not reaching the backend.** A route declared as `/api/v1/customers`
   matches only that exact path in `net/http`'s `ServeMux` — it does *not* cover
   `/api/v1/customers/7`. Prefix routes need the trailing slash. Step `3b`
   probes representative paths and aborts if any is not `200`.
2. **Export silently rate-limited.** The admin plane throttles itself (5 req/s,
   brute-force protection), so a tight export loop gets `Access Denied` written
   into the artifact instead of JSON. `fetch()` paces, retries and validates each
   response.

## Regenerating after a product change

Re-run both commands. If the numbers in the report move, that is the product
telling you something changed — reconcile it before shipping the new PDF, don't
paper over it.
