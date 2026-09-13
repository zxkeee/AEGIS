# False-positive assessment — AEGIS against a real, third-party API

Stands AEGIS in front of a public Forgejo (Codeberg), drives genuine read-only
browsing through it, and exports every finding for manual review.

Nothing here is adversarial and nothing is planted. Every request is something
an ordinary user, a CI job or a code-search indexer would send, against an API
nobody wrote to be found wanting. So **any finding is a false positive unless it
describes a real property of that API** — which is the one thing the sample
report in `demo/sample-report/` cannot tell you, because its backend is
deliberately flawed and every detection there was put in on purpose.

```bash
POSTGRES_DSN='postgres://…' ./demo/fp-assessment/run.sh
```

Needs `go`, `curl`, `redis-server`, `psql` and a reachable PostgreSQL. Exports
land in `out/` (gitignored). Traffic is paced at 4 req/s on a single connection
— Codeberg is volunteer-run infrastructure and this is someone else's service.

## Why it exists

Run for the first time on 2026-08-31, it produced **101 critical findings from
161 requests**, none of which would have survived a customer's review. Months of
testing against a synthetic backend had shown nothing of the kind, because a
backend written to be insecure cannot tell you what your product says about code
that is merely ordinary.

Four structural failures came out of that first hour:

| Failure | Status |
|---|---|
| `credit_card` matched an ORCID, `phone` matched unix timestamps in commit metadata | fixed, `f856878` |
| `owner_fields` could not read a nested owner (`user.id`), so confirmed-IDOR never fired on any real API | fixed, `f856878` |
| Path normalisation collapsed only digit-shaped segments, so a slug-keyed API produced one catalog row per object | fixed, `internal/discovery/learn.go` |
| Consumer identity came from a verified JWT `sub` only, so an API using opaque tokens collapsed to a single `ip:` consumer, and BOLA/BFLA with it | fixed, `security.consumer_id` |

Measured over the same traffic pattern at pilot scale (1035 requests):

|                     | before | after |
|---------------------|-------:|------:|
| catalog "endpoints" |    500 |    13 |
| findings            |    380 |    10 |
| false type claims (PCI/phone) | 9 | 0 |
| distinct consumers  |      1 |     4 |

The three token-carrying personas in `traffic.py` are now separated, and their
shapes match what they are: 500 requests over 2 endpoints for the indexer, 370
over 9 for the developer, 160 over 2 for profile browsing.

## Reading the output

`out/findings.json` is the artifact to review. Go through it line by line and
classify each finding as true, arguable or false — the number that matters is
the share a customer would throw away, not the total. `out/catalog.json` shows
whether the inventory looks like an API or like a request log.

The residual 10 findings are `sensitive_data_no_auth` on endpoints that really
do return committer email addresses to anonymous callers. The detection is
correct; calling it *critical* on a public code host was not.

**Fixed 2026-09-14.** Severity now follows the data class: PCI (card numbers)
and PHI stay critical, ordinary PII — an email, a phone number — is a warning.
An email served to an anonymous caller is frequently deliberate (a public
profile, a commit author, a support address) and only the operator can say which
it is; a card number never is. A mixture grades by its worst class.

The same run now produces **10 findings, all warning**. The detection did not
change — the same ten endpoints, the same code — only the grade. That is the
intended outcome: grading is not filtering, and an exposure an operator decides
is deliberate should be decided from a list rather than from silence.

Why this mattered more than it looks: ten criticals that are all the same benign
fact teach an operator to skim the list, and the eleventh finding is the card
number.

### Two things the re-run surfaced

**193 of 1036 requests came back 409** from Codeberg (837×200, 6×404,
193×409). Forgejo answers 409 for some repository states, and the pacing is
already conservative, so this is the upstream's behaviour rather than the
gateway's — but it means the effective sample is ~837 requests, not 1036. Worth
knowing before quoting the numbers.

**The posture export never worked.** `run.sh` fetched `/api/posture`; the route
is `/api/posture/summary`. It had been writing an empty file and printing a
failure line nobody read since the script was written. Fixed.

## Keeping it honest

Re-run it after any change to detection or classification and record the numbers
above. "We reduced false positives" is a claim; this is the measurement behind
it. The path dataset in `internal/discovery/testdata/codeberg_paths.txt` is the
exact request stream from a run, replayed by the path learner's unit tests —
thresholds in that package are fitted against it rather than against invented
traffic, which is how the first attempt got them wrong.
