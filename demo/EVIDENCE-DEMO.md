# AEGIS — evidence demo

The three minutes that sell the product. Everything else in API security ends
at a dashboard; this ends at a document an assessor checks **without trusting
the operator, the vendor, or the gateway**.

## Run it

```bash
make demo          # interactive: press Enter between steps (for a live audience)
make demo-auto     # straight through, no pauses
```

Requires what `scripts/pentest-stand.sh` requires: `go`, `curl`, `redis-server`,
PostgreSQL, `openssl`. `jq` and `python3` make the output prettier. Everything
is torn down on exit.

## The story, step by step

| Step | What the audience sees | The point |
|---|---|---|
| ① | 18 ordinary requests through the gateway, one SQL injection blocked | Nothing is staged — every number below comes from these requests |
| ② | The catalog: two endpoints, normalised paths, `credit_card, email, phone` on one of them, **6 of 6 callers anonymous** | Discovered from traffic, no spec imported. The injection never appears: the WAF stopped it before the catalog saw it |
| ③ | `GET /api/report/signing-key` → a `key_id` | **The one fact the auditor must get from somewhere other than the report** |
| ④ | The signed report: NIS2 Art. 21(2)(h) tied to the observed PII exposure, Art. 21(2)(i) tied to 8 enumeration events — and **3 controls named as NOT evidenced** | A regulation article tied to an observation, and an honest gap list |
| ⑤ | `reportverify -in report.json -key-id …` → `OK` | The document is exactly what was signed |
| ⑥ | One integer incremented, signature untouched → **digest mismatch, exit 1** | Tampering is detected, not argued about |
| ⑦ | The genuine report against a *different* pinned key → **refused** | The report names which key actually signed it |
| ⑧ | `reportverify -in report.json` with no pinned key → **refuses to run** | The moment that makes the rest mean anything |

## How to present it

1. **Lead with the auditor, not the gateway.** "Your supervisory authority asks
   how you know this endpoint was protected in Q2. What do you hand them?"
2. Let ② sit for a second. Six requests, six anonymous callers, card data in the
   response. Nobody configured that — it was observed.
3. **④ is where the regulation becomes concrete.** Read one row out loud:
   *NIS2 Art. 21(2)(h), critical: sensitive data exposed to unauthenticated
   callers — GET /public/customers/{id}.* That is not a risk score, it is an
   article and an endpoint.
4. Then read the `not_evidenced` list. *"DORA Art. 19 — filing the report
   remains a human act."* A compliance product that tells you what it does
   **not** cover is making a claim the others cannot afford to make.
5. **⑧ is the close.** A signed report carries the key that signed it, so
   checking a report against itself always succeeds and proves nothing — a
   forger supplies both halves. The tool refuses. Say it plainly: *"That refusal
   is what you are buying. Everything else is a screenshot."*

## What this demo does not claim

Be ready for the competent question, because it is a good one:

> *The signature proves the document. What proves the log it was computed from?*

Today: nothing. The forensic log is an ordinary table, and the retention sweep
deletes from it. Tamper-evident chaining and an external timestamp authority are
the next increment, and they are named openly rather than implied — see
`SECURITY.md`. Saying so is the same discipline the demo is selling.

## Why the catalog is reset first

The script truncates the catalog before driving traffic. The stand keeps its
PostgreSQL between runs, and without the reset the counts accumulate: 18
requests were being reported as 84 events on the third rehearsal. A number in
the report has to describe the run the audience just watched.
